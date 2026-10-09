# 실행: htb-agent 디렉토리에서  python3 tests/test_llm.py
import sys
sys.path.insert(0, "src")
from htb_agent.llm.base import Tier
from htb_agent.llm.fake_provider import FakeProvider
from htb_agent.llm.router import LLMRouter
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.runner import FakeRunner, RunOutput
from htb_agent.tools.recon import auto_approve_in_scope
from htb_agent.knowledge import KnowledgeBase
from htb_agent.orchestrator import Orchestrator

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== 티어 모델 매핑 ===")
p = FakeProvider("x")
check("cheap/standard/strong 모델 상이",
      len({p.model_for(Tier.CHEAP), p.model_for(Tier.STANDARD), p.model_for(Tier.STRONG)}) == 3)

print("\n=== 라우터 파싱(후보 정제) ===")
fake_text = """\
nmap -sV {t}
- gobuster dir -u http://{t} -w /tmp/w.txt
1. whatweb http://{t}
nmap -sV {t}
evil-winrm -i {t} -u {user} -p {pass}
```
# 주석줄
"""
router = LLMRouter(FakeProvider(fake_text), max_items=10)
cmds = router.suggest_commands({"profile": "linux"}, "10.129.1.5")
check("{t} 치환", all("10.129.1.5" in c for c in cmds))
check("번호/불릿 제거", any(c.startswith("whatweb") for c in cmds) and any(c.startswith("gobuster") for c in cmds))
check("중복 제거", cmds.count("nmap -sV 10.129.1.5") == 1)
check("크리덴셜 플레이스홀더 라인 제외", all("evil-winrm" not in c for c in cmds))
check("주석/코드펜스 제외", all(not c.startswith("#") and "```" not in c for c in cmds))

print("\n=== 티어 전달 ===")
seen = {}
def responder(system, user, tier):
    seen["tier"] = tier
    return "nmap -sV {t}"
LLMRouter(FakeProvider(responder)).suggest_commands({}, "10.129.1.5", tier=Tier.STRONG)
check("지정 티어 전달됨", seen.get("tier") == Tier.STRONG)

print("\n=== 오케스트레이터 + LLM (게이트 적용) ===")
LINUX_WEB = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.129.1.5"/><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache"/></port>
</ports></host></nmaprun>"""
def guard():
    g = ScopeGuard.from_cidr_strings(); g.bind_target("10.129.1.5"); return g
def runner_responder(cmd):
    if cmd.startswith("nmap"): return RunOutput(cmd, stdout=LINUX_WEB)
    return RunOutput(cmd, stdout="ok-output")
ALL = lambda b: True

# LLM 이 범위내 명령 제안 → 게이트 통과 → 실행
llm = LLMRouter(FakeProvider("ffuf -u http://{t}/FUZZ -w /tmp/w.txt"))
r = FakeRunner(runner_responder)
orc = Orchestrator(guard(), r, KnowledgeBase.load(), auto_approve_in_scope,
                   llm_router=llm, is_tool_available=ALL)
rep = orc.run()
check("LLM 제안 실행됨", any(f.ran for f in rep.llm_findings))

# LLM 이 범위밖 대상 제안 → 범위 게이트가 차단(자동승인 거부)
llm_bad = LLMRouter(FakeProvider("nmap -sV 8.8.8.8"))
r = FakeRunner(runner_responder)
orc = Orchestrator(guard(), r, KnowledgeBase.load(), auto_approve_in_scope,
                   llm_router=llm_bad, is_tool_available=ALL)
rep = orc.run()
check("범위밖 LLM 명령 차단(미실행)",
      all(not f.ran for f in rep.llm_findings) and
      any("미승인" in f.note for f in rep.llm_findings))

# max_llm 상한
llm_many = LLMRouter(FakeProvider("curl -i http://{t}/a\ncurl -i http://{t}/b\ncurl -i http://{t}/c"))
r = FakeRunner(runner_responder)
orc = Orchestrator(guard(), r, KnowledgeBase.load(), auto_approve_in_scope,
                   llm_router=llm_many, max_llm=2, is_tool_available=ALL)
rep = orc.run()
check("LLM 상한 준수(<=2)", len(rep.llm_findings) <= 2)

# LLM 백엔드 예외 → 전체 안 깨짐
class Boom(FakeProvider):
    def complete(self, *a, **k): raise RuntimeError("boom")
orc = Orchestrator(guard(), FakeRunner(runner_responder), KnowledgeBase.load(),
                   auto_approve_in_scope, llm_router=LLMRouter(Boom("x")), is_tool_available=ALL)
rep = orc.run()
check("LLM 오류 시 graceful", rep.status == "done" and any("LLM 제안 실패" in s for s in rep.manual_suggestions))

print("\n=== ① 분석가 티어 적응화: 첫 분석(기록 없음)은 STRONG ===")
# analyze 호출(분석가 시스템 프롬프트)만 티어를 기록한다. 첫 분석은 가설 기록이 없어 STRONG.
seen_analyst_tiers = []
def tier_responder(system, user, tier, max_tokens=1024, tools=None):
    from htb_agent.llm.base import LLMResponse
    if "분석가" in system:
        seen_analyst_tiers.append(tier)
        return LLMResponse(text="가설:\n  H1 [우선:상] 테스트 — 근거 〔추정〕\n확신도: 중", model="m")
    return LLMResponse(text="curl -i http://{t}/a", model="m")
orc = Orchestrator(guard(), FakeRunner(runner_responder), KnowledgeBase.load(),
                   auto_approve_in_scope, llm_router=LLMRouter(FakeProvider(tier_responder)),
                   is_tool_available=ALL)
orc.run()
check("첫 분석가 호출은 STRONG(opus) 티어",
      bool(seen_analyst_tiers) and seen_analyst_tiers[0] == Tier.STRONG)

print("\n=== ④ 모든 가설 막힘이면 투기적 LLM 라운드 건너뜀 ===")
from htb_agent.hypotheses import HypothesisLedger
led = HypothesisLedger(replan_after=1)
led.apply_text('가설기록: {"hypotheses":[{"id":"H1","text":"x","priority":"상",'
               '"status":"testing","check":"c","expected":"sig","fallback":"f"}]}')
led.record("H1", "cmd", "", ran=True, target_rejected=True)   # 대상 거부 → miss(replan_after=1 → 막힘)
check("H1 막힘 처리", bool(led.stuck()) and led.focus() is None and bool(led.items))

print("\n=== 캐시 친화: 시스템 프롬프트 고정 + 라운드 상한은 사용자 프롬프트로 ===")
# suggest 가 호출마다 변하는 잔여 예산(max_items)을 시스템 프롬프트에 박지 않는다(ephemeral 캐시 적중).
seen_systems = []
def cap_responder(system, user, tier, max_tokens=1024, tools=None):
    seen_systems.append(system)
    from htb_agent.llm.base import LLMResponse
    return LLMResponse(text="curl -i http://{t}/a", model="m")
cap_router = LLMRouter(FakeProvider(cap_responder), max_items=5)
cap_router.suggest_commands({}, "10.129.1.5", max_items=2)
cap_router.suggest_commands({}, "10.129.1.5", max_items=4)
check("시스템 프롬프트는 라운드 상한과 무관하게 동일(캐시 적중)",
      len(seen_systems) == 2 and seen_systems[0] == seen_systems[1])

from htb_agent.llm.router import LLMRouter as _LR
up = _LR._user_prompt({}, "10.129.1.5", round_limit=2)
check("라운드 상한은 사용자 프롬프트에 명시", "최대 2개" in up)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
