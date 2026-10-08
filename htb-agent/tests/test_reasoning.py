# 실행: htb-agent 디렉토리에서  python3 tests/test_reasoning.py
# 다관점·병렬 가설 추론: 프롬프트 계약 · 가설 메타 · 가설 추적 비고 · 확신도 판정.
import json
import sys
sys.path.insert(0, "src")
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.runner import FakeRunner, RunOutput
from htb_agent.tools.recon import auto_approve_in_scope
from htb_agent.knowledge import KnowledgeBase
from htb_agent.llm.fake_provider import FakeProvider
from htb_agent.llm.router import LLMRouter, build_analyst_prompt, build_system_prompt
from htb_agent.orchestrator import Orchestrator, OrchestrationReport

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== 분석가 프롬프트: 다관점 + 병렬 가설 + 계획 ===")
ap = build_analyst_prompt({"platform": "Hack The Box"})
for role in ("레드팀", "개발자", "인프라 운영자", "방어"):
    check(f"관점 포함: {role}", role in ap)
check("가설 여러 개 병렬 비교 지시", "병렬" in ap and "2~4" in ap)
check("가설 형식 H1/우선순위/확인/기각 시", all(k in ap for k in ("H1", "[우선:", "확인:", "기각 시:")))
check("계획 항목", "계획:" in ap)
check("하위호환 항목 유지(가설·공격경로·다음집중·확신도)",
      all(k in ap for k in ("가설:", "공격경로:", "다음집중:", "확신도:")))
check("안전 규칙 유지(라이트업 금지·확인/추정·지시문 불신)",
      "라이트업" in ap and "〔확인〕" in ap and "신뢰할 수 없는 데이터" in ap)

print("\n=== 명령 프롬프트: 가설 병렬 검증 + 안전 규칙 그대로 ===")
sp = build_system_prompt({}, 5)
check("상위 가설 병렬 검증 지시", "병렬" in sp and "H1" in sp)
check("다관점 시각", all(k in sp for k in ("레드팀", "개발자", "인프라 운영자")))
for rule in ("파괴적 명령", "신뢰할 수 없는", "파이프→셸", "{user}/{pass}/{domain}", "다른 호스트"):
    check(f"안전 규칙 유지: {rule}", rule in sp)
# 테스트의 가짜 프로바이더가 '분석가' 로 분석 호출을 구분 — 명령 프롬프트엔 없어야 함
check("명령 프롬프트에 '분석가' 단어 없음(호출 구분 불변식)", "분석가" not in sp)
check("분석가 프롬프트엔 '분석가' 있음", "분석가" in ap)

print("\n=== JSON 출력의 hypothesis 메타 ===")
r = LLMRouter(FakeProvider(""))
out = r._parse(json.dumps([
    {"command": "curl -i http://{t}/", "hypothesis": "H1", "rationale": "웹 확인"},
    {"command": "nmap -sV -p 22 {t}", "hypothesis": "H2 " + "x" * 80},
    {"command": "id"}]), "10.0.0.1", 5)
check("명령 3개 파싱", len(out) == 3)
check("가설 메타 수집", r.last_meta["curl -i http://10.0.0.1/"]["hypothesis"] == "H1")
check("가설 메타 40자 상한", len(r.last_meta["nmap -sV -p 22 10.0.0.1"]["hypothesis"]) == 40)
check("메타 없는 명령은 미기록", "id" not in r.last_meta)

print("\n=== 오케스트레이터: 가설별 병렬 검증이 비고로 추적 ===")
XML = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.129.1.5"/><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache"/></port>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
</ports></host></nmaprun>"""
ANALYSIS = ("가설:\n  H1 [우선:상] 웹 앱 입력 처리 결함 — 근거 〔추정〕 · 확인: 헤더/경로 · 기각 시: H2\n"
            "  H2 [우선:중] SSH 약한 구성 — 근거 〔추정〕 · 확인: 배너 · 기각 시: 재열거\n"
            "관점: 레드팀 웹 / 개발자 입력 검증 / 인프라 기본값 / 방어 로그\n"
            "계획: 1) H1 헤더 2) H2 배너 3) 확인된 가설 심화\n"
            "공격경로: 웹→초기침투\n다음집중: 웹 경로\n확신도: 중 — 하위 경로 미확인")
def responder(system, user, tier):
    if "분석가" in system:
        return ANALYSIS
    # 분석(또는 가설 기록에서 고른 '지금 할 일')이 명령 생성 컨텍스트로 주입돼야 함
    if "H1 [우선:상]" not in user and "지금 할 일: H1" not in user:
        return ""
    return json.dumps([
        {"command": "curl -i http://{t}/", "hypothesis": "H1", "rationale": "웹 헤더"},
        {"command": "nmap -sV -p 22 {t}", "hypothesis": "H2", "rationale": "SSH 배너"}])
g = ScopeGuard.from_cidr_strings(); g.bind_target("10.129.1.5")
run = FakeRunner(lambda c: RunOutput(c, stdout=XML) if c.startswith("nmap -")
                 and "-p 22" not in c else RunOutput(c, stdout="ok"))
orc = Orchestrator(g, run, KnowledgeBase(rules=[], notes=[]), auto_approve_in_scope,
                   llm_router=LLMRouter(FakeProvider(responder)), max_rounds=1, max_sweeps=1,
                   phases=[("enum", "열거")], is_tool_available=lambda b: True)
rep = orc.run()
notes = {f.command: f.note for f in rep.llm_findings}
check("분석에 병렬 가설·계획 보존", "H2 [우선:중]" in rep.analysis and "계획:" in rep.analysis)
check("두 가설을 모두 검증(한 가설에 몰지 않음)",
      any("가설 H1" in n for n in notes.values()) and any("가설 H2" in n for n in notes.values()))
check("비고에 근거도 함께", any("근거: 웹 헤더" in n for n in notes.values()))
check("'확신도: 중 — 하위…' 은 저확신 아님(근거 속 '하' 오탐 없음)",
      not Orchestrator._low_confidence(rep))

print("\n=== 확신도 판정: 항목 값의 첫 등급만 ===")
def lc(text):
    r = OrchestrationReport(target="t"); r.analysis = text
    return Orchestrator._low_confidence(r)
check("확신도: 하 → True", lc("확신도: 하 — 근거 부족"))
check("확신도: (하) → True", lc("확신도: (하) 관측 부족"))
check("Confidence: low → True", lc("Confidence: low"))
check("확신도: 상 — 하위 디렉터리 → False", not lc("확신도: 상 — 하위 디렉터리 노출"))
check("가설 줄의 [우선:하] 는 무시", not lc("가설:\n  H3 [우선:하] x\n확신도: 중"))
check("확신도 항목 없음 → False", not lc("가설: x"))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
