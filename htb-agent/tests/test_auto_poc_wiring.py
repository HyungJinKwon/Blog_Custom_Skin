# 실행: htb-agent 디렉토리에서  python3 tests/test_auto_poc_wiring.py
#
# ②(d) --auto-poc 배선 회귀 가드: Orchestrator 가 auto_poc 파라미터를 받고(기본 False),
# exploit_exec+auto_poc 일 때만 ⭐ 버전매칭 PoC 실행계획을 poc_commands 에 자동 투입하는지 검증.
# (auto_poc 파라미터 누락으로 생성 자체가 NameError 로 깨지던 회귀를 막는다.)
import sys
sys.path.insert(0, "src")
from htb_agent.scope_guard import ScopeGuard                        # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput            # noqa: E402
from htb_agent.tools.recon import auto_approve_in_scope             # noqa: E402
from htb_agent.knowledge import KnowledgeBase                       # noqa: E402
from htb_agent.orchestrator import Orchestrator, OrchestrationReport  # noqa: E402
from htb_agent.world import WorldModel                              # noqa: E402
from htb_agent.observation.parsers import NmapHost, Port            # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

TARGET = "10.129.245.100"
SS = ("Exploit Title | Path\n"
      " FreePBX 13.0.188 - Remote Command Execution | php/remote/40434.rb\n")

def mk(auto_poc, exploit_exec):
    g = ScopeGuard.from_cidr_strings(); g.bind_target(TARGET)
    runner = FakeRunner(lambda c: RunOutput(c, stdout=SS))
    o = Orchestrator(g, runner, KnowledgeBase.load(), auto_approve_in_scope,
                     flag_kind="boot2root", is_tool_available=lambda b: True,
                     exploit_exec=exploit_exec, auto_poc=auto_poc)
    o._start = o._clock(); o._deadline = None
    o.world = WorldModel(target=TARGET)
    o.world.set_web_app("freepbx", "13.0.188")
    return o

host = NmapHost(address=TARGET, state="up")
host.ports = [Port(443, "tcp", "open", service="https")]

print("=== Orchestrator auto_poc 파라미터(회귀 가드) ===")
check("auto_poc 기본 False", mk(False, False).auto_poc is False)
check("auto_poc=True 수용", mk(True, True).auto_poc is True)

print("\n=== ⭐ 매칭 시 auto_poc 자동 투입 ===")
o = mk(True, True)
rep = OrchestrationReport(target=TARGET, flag_kind="boot2root")
o._exploit_lookup_stage(rep, host)
check("auto_poc+exploit_exec → poc_commands 에 계획 투입", len(o.poc_commands) == 1)
check("투입된 계획이 ⭐ 1순위 PoC 명령", o.poc_commands and "40434" in o.poc_commands[0])

print("\n=== auto_poc 꺼짐 → 투입 안 함(제안만) ===")
o2 = mk(False, True)
rep2 = OrchestrationReport(target=TARGET, flag_kind="boot2root")
o2._exploit_lookup_stage(rep2, host)
check("auto_poc=False → poc_commands 비어 있음", o2.poc_commands == [])
check("그래도 실행계획 '제안'은 수동제안에 존재",
      any("실행 계획(제안" in m for m in rep2.manual_suggestions))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
