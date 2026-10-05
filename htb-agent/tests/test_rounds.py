# 실행: htb-agent 디렉토리에서  python3 tests/test_rounds.py
# 반복 피드백 루프: 이전 관측이 다음 LLM 제안에 반영 + 유한 상한 검증.
import sys
sys.path.insert(0, "src")
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.runner import FakeRunner, RunOutput
from htb_agent.tools.recon import auto_approve_in_scope
from htb_agent.knowledge import KnowledgeBase
from htb_agent.llm.fake_provider import FakeProvider
from htb_agent.llm.router import LLMRouter
from htb_agent.orchestrator import Orchestrator

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

XML = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.129.1.5"/><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache"/></port>
</ports></host></nmaprun>"""

def guard():
    g = ScopeGuard.from_cidr_strings(); g.bind_target("10.129.1.5"); return g
def runner():
    return FakeRunner(lambda c: RunOutput(c, stdout=XML) if c.startswith("nmap")
                      else RunOutput(c, stdout="output-data"))
# KB 최소화: 빈 KB 로 LLM 효과만 관찰
EMPTY_KB = KnowledgeBase(rules=[], notes=[])

# 적응형 FakeProvider: 이전 관측(findings)에 gobuster 결과가 보이면 다른 명령 제안.
# B3 분석가 호출(system 에 '분석가')은 명령이 아닌 중립 분석을 반환해 명령 감지를 오염시키지 않음.
def adaptive(system, user, tier):
    if "분석가" in system:          # B3 분석가 호출 — 중립 분석(명령어 토큰 미포함)
        return "가설: 웹 서비스 중심\n공격경로: 웹→초기침투\n다음집중: 디렉토리 열거\n확신도: 중"
    if "nuclei" in user:            # 라운드3 이상 — 더 제안 안 함(종료 유도)
        return "nuclei -u http://{t}"
    if "gobuster" in user:          # 라운드2: 이전에 gobuster 가 돌았음 → 새 명령
        return "nuclei -u http://{t}"
    return "gobuster dir -u http://{t} -w /tmp/w.txt"   # 라운드1

print("=== 적응형 반복 라운드 ===")
llm = LLMRouter(FakeProvider(adaptive))
orc = Orchestrator(guard(), runner(), EMPTY_KB, auto_approve_in_scope,
                   llm_router=llm, max_rounds=3, is_tool_available=lambda b: True)
rep = orc.run()
cmds = [f.command for f in rep.llm_findings]
check("라운드1 gobuster 실행", any("gobuster" in c for c in cmds))
check("라운드2 적응해 nuclei 제안(새 명령)", any("nuclei" in c for c in cmds))
check("중복 명령 재실행 안 함", len(cmds) == len(set(cmds)))

print("\n=== max_rounds=1 + max_sweeps=1 → 단일 라운드만 ===")
# 단일 단계(enum)·단일 스윕·max_rounds=1 → round1 gobuster 만, 적응 라운드 없음
orc = Orchestrator(guard(), runner(), EMPTY_KB, auto_approve_in_scope,
                   llm_router=LLMRouter(FakeProvider(adaptive)), max_rounds=1,
                   max_sweeps=1, phases=[("enum", "열거")], is_tool_available=lambda b: True)
rep = orc.run()
cmds = [f.command for f in rep.llm_findings]
check("1라운드: gobuster만", any("gobuster" in c for c in cmds) and not any("nuclei" in c for c in cmds))

print("\n=== A1 재진입 스윕: max_rounds=1 이어도 다음 스윕서 적응 ===")
# max_rounds=1 이라도 max_sweeps=2 면 스윕2에서 gobuster 관측 반영→nuclei 제안
orc = Orchestrator(guard(), runner(), EMPTY_KB, auto_approve_in_scope,
                   llm_router=LLMRouter(FakeProvider(adaptive)), max_rounds=1,
                   max_sweeps=2, phases=[("enum", "열거")], is_tool_available=lambda b: True)
rep = orc.run()
cmds = [f.command for f in rep.llm_findings]
check("스윕2에서 nuclei 적응 제안", any("nuclei" in c for c in cmds))

print("\n=== 상태 정체 시 스윕 조기 종료(무한 아님) ===")
# 항상 같은 명령 → 스윕1 후 성장 없음 → 스윕2 돌아도 중복뿐, 1건만
same2 = LLMRouter(FakeProvider("curl -i http://{t}/"))
orc = Orchestrator(guard(), runner(), EMPTY_KB, auto_approve_in_scope,
                   llm_router=same2, max_rounds=5, max_sweeps=3, is_tool_available=lambda b: True)
rep = orc.run()
check("정체 시 중복 없이 1건", len(rep.llm_findings) == 1)

print("\n=== 새 명령 없으면 조기 종료 ===")
# 항상 같은 명령 → 라운드2에서 0건 추가 → 조기 종료(중복 1건만)
same = LLMRouter(FakeProvider("curl -i http://{t}/"))
orc = Orchestrator(guard(), runner(), EMPTY_KB, auto_approve_in_scope,
                   llm_router=same, max_rounds=5, is_tool_available=lambda b: True)
rep = orc.run()
check("동일 제안 반복 시 1건만(조기종료)", len(rep.llm_findings) == 1)

print("\n=== 전역 max_llm 상한(라운드 합산) ===")
multi = LLMRouter(FakeProvider("curl -i http://{t}/a\ncurl -i http://{t}/b\ncurl -i http://{t}/c\ncurl -i http://{t}/d"))
orc = Orchestrator(guard(), runner(), EMPTY_KB, auto_approve_in_scope,
                   llm_router=multi, max_rounds=5, max_llm=2, is_tool_available=lambda b: True)
rep = orc.run()
check("LLM 총 상한 2 준수", len(rep.llm_findings) <= 2)

print("\n=== B3 분석가: report.analysis 산출 + 명령 생성에 주입 ===")
# 분석가 호출(system '분석가')엔 분석을, 명령 호출엔 analysis 반영 여부로 분기
def analyst_aware(system, user, tier):
    if "분석가" in system:
        return "가설: SSH 약자격 의심\n공격경로: SSH→user\n다음집중: 자격 추측\n확신도: 중"
    # 명령 생성: 분석가 판단이 user 프롬프트에 주입됐는지 확인되면 특정 명령
    if "SSH 약자격" in user:
        return "hydra -l root ssh://{t}"
    return "curl -i http://{t}/"
orc = Orchestrator(guard(), runner(), EMPTY_KB, auto_approve_in_scope,
                   llm_router=LLMRouter(FakeProvider(analyst_aware)), max_rounds=1,
                   max_sweeps=1, phases=[("enum", "열거")], is_tool_available=lambda b: True)
rep = orc.run()
check("report.analysis 채워짐", "가설:" in rep.analysis)
check("분석가 판단이 명령 생성에 주입됨", any("hydra" in f.command for f in rep.llm_findings))

print("\n=== LLM 없으면 분석 생략(비파괴) ===")
orc = Orchestrator(guard(), runner(), EMPTY_KB, auto_approve_in_scope,
                   is_tool_available=lambda b: True)
rep = orc.run()
check("LLM 없음 → analysis 빈 문자열", rep.analysis == "")

print("\n=== B4 구조화(JSON) 출력 파싱 ===")
r = LLMRouter(FakeProvider(""))
# JSON 배열(객체) — command/rationale/expected_signal
js = r._parse('[{"command":"nmap -sV {t}","rationale":"버전 식별","expected_signal":"서비스 배너"},'
              '{"command":"curl -i http://{t}/","rationale":"헤더 확인"}]', "10.0.0.1", 5)
check("JSON 객체 배열 파싱", js == ["nmap -sV 10.0.0.1", "curl -i http://10.0.0.1/"])
check("근거 메타 수집", r.last_meta.get("nmap -sV 10.0.0.1", {}).get("rationale") == "버전 식별")
check("기대신호 메타 수집", r.last_meta.get("nmap -sV 10.0.0.1", {}).get("expected") == "서비스 배너")
# JSON 문자열 배열
js2 = r._parse('["id", "whoami"]', "t", 5)
check("JSON 문자열 배열 파싱", js2 == ["id", "whoami"])
# ```json 펜스 허용
js3 = r._parse('```json\n[{"command":"ls -la"}]\n```', "t", 5)
check("코드펜스 JSON 파싱", js3 == ["ls -la"])
# 플레이스홀더 남으면 제외
js4 = r._parse('[{"command":"nxc smb {t} -u {user} -p {pass}"}]', "t", 5)
check("JSON 내 플레이스홀더 명령 제외", js4 == [])
# 라인 폴백(JSON 아님)
lf = r._parse("nmap -sC {t}\ncurl http://{t}/", "9.9.9.9", 5)
check("비-JSON 라인 폴백", lf == ["nmap -sC 9.9.9.9", "curl http://9.9.9.9/"])
check("폴백 시 메타 비움", r.last_meta == {})

print("\n=== B4 근거가 finding 비고에 반영 ===")
def json_prov(system, user, tier):
    if "분석가" in system:
        return "가설: x\n공격경로: y\n다음집중: z\n확신도: 중"
    return '[{"command":"curl -i http://{t}/","rationale":"응답 헤더로 기술스택 식별"}]'
orc = Orchestrator(guard(), runner(), EMPTY_KB, auto_approve_in_scope,
                   llm_router=LLMRouter(FakeProvider(json_prov)), max_rounds=1,
                   max_sweeps=1, phases=[("enum", "열거")], is_tool_available=lambda b: True)
rep = orc.run()
check("JSON 명령 실행됨", any("curl" in f.command for f in rep.llm_findings))
check("근거가 비고에 반영", any("근거:" in (f.note or "") for f in rep.llm_findings))

print("\n=== B6 적응형 tier: 빈 결과 → 강력 모델 승격 재시도 ===")
from htb_agent.llm.base import Tier
# cheap/standard 는 빈 응답, strong 에서만 명령 반환 → 승격되어야 명령이 나옴
def tier_gated(system, user, tier):
    if "분석가" in system:
        return "가설: x\n공격경로: y\n다음집중: z\n확신도: 중"
    return "curl -i http://{t}/" if tier == Tier.STRONG else ""
orc = Orchestrator(guard(), runner(), EMPTY_KB, auto_approve_in_scope,
                   llm_router=LLMRouter(FakeProvider(tier_gated)), max_rounds=1,
                   max_sweeps=1, phases=[("enum", "열거")], is_tool_available=lambda b: True)
rep = orc.run()
check("빈 결과 → strong 승격으로 명령 확보", any("curl" in f.command for f in rep.llm_findings))

print("\n=== B6 적응형 tier: 저확신 → 처음부터 강력 ===")
# 분석가가 확신도 '하' → 첫 호출부터 strong. strong 일 때만 명령 반환해 확인
calls = {"standard": 0, "strong": 0}
def conf_gated(system, user, tier):
    if "분석가" in system:
        return "가설: x\n공격경로: y\n다음집중: z\n확신도: 하(근거 약함)"
    calls[tier.value if hasattr(tier, "value") else str(tier)] = \
        calls.get(tier.value if hasattr(tier, "value") else str(tier), 0) + 1
    return "nmap -sV {t}" if tier == Tier.STRONG else ""
orc = Orchestrator(guard(), runner(), EMPTY_KB, auto_approve_in_scope,
                   llm_router=LLMRouter(FakeProvider(conf_gated)), max_rounds=1,
                   max_sweeps=1, phases=[("enum", "열거")], is_tool_available=lambda b: True)
rep = orc.run()
check("저확신 → strong 명령 확보", any("nmap" in f.command for f in rep.llm_findings))

print("\n=== B6 _low_confidence 판정 ===")
from htb_agent.orchestrator import OrchestrationReport
r_lo = OrchestrationReport(target="t"); r_lo.analysis = "확신도: 하 — 근거 부족"
r_mid = OrchestrationReport(target="t"); r_mid.analysis = "확신도: 중"
r_none = OrchestrationReport(target="t")
check("확신도 하 → True", Orchestrator._low_confidence(r_lo))
check("확신도 중 → False", not Orchestrator._low_confidence(r_mid))
check("분석 없음 → False", not Orchestrator._low_confidence(r_none))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
