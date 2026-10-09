# 실행: htb-agent 디렉토리에서  python3 tests/test_foothold_degrade.py
#
# 회귀: ② _foothold_stage 배선 후, 웹 RCE 전송부(shell_transport)가 requests 미설치로
# import 실패해도 '전체 실행 크래시'가 아니라 '발판 미확보'로 안전하게 degrade 해야 한다.
# (connected.htb 재실행에서 ModuleNotFoundError: requests 로 run 전체가 죽던 문제.)
import sys
sys.path.insert(0, "src")
from htb_agent.scope_guard import ScopeGuard                   # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput       # noqa: E402
from htb_agent.tools.recon import auto_approve_in_scope        # noqa: E402
from htb_agent.knowledge import KnowledgeBase                  # noqa: E402
from htb_agent.orchestrator import Orchestrator, OrchestrationReport  # noqa: E402
from htb_agent.world import WorldModel                         # noqa: E402
from htb_agent.observation.parsers import NmapHost, Port       # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

TARGET = "10.129.245.100"

def guard():
    g = ScopeGuard.from_cidr_strings(); g.bind_target(TARGET); return g

def mk_orc():
    o = Orchestrator(guard(), FakeRunner(lambda c: RunOutput(c, stdout="")),
                     KnowledgeBase.load(), auto_approve_in_scope,
                     flag_kind="boot2root", is_tool_available=lambda b: True,
                     exploit_exec=True, auto_poc=True)
    o._start = o._clock(); o._deadline = None
    o.world = WorldModel(target=TARGET)
    o.world.set_web_app("freepbx", "16.0.40.7")
    return o

def mk_host():
    h = NmapHost(address=TARGET, state="up")
    h.ports = [Port(443, "tcp", "open", service="https")]
    return h

print("=== _acquire_session: requests(shell_transport) 미설치 degrade ===")
orc = mk_orc()
rep = OrchestrationReport(target=TARGET, flag_kind="boot2root")
# shell_transport import 를 강제로 실패시킴(= requests 미설치와 동일한 ImportError 경로)
saved = sys.modules.get("htb_agent.shell_transport")
sys.modules["htb_agent.shell_transport"] = None   # import 시 ImportError 유발
try:
    result = orc._acquire_session(rep, mk_host())   # 크래시 없어야 함
    crashed = False
except Exception as e:                              # noqa: BLE001 — 테스트: 크래시 여부 확인
    result = e
    crashed = True
finally:
    if saved is not None:
        sys.modules["htb_agent.shell_transport"] = saved
    else:
        sys.modules.pop("htb_agent.shell_transport", None)

check("import 실패해도 크래시 없음(안전 degrade)", not crashed)
check("발판 미확보로 None 반환", result is None)
check("requests 미설치 안내가 수동 제안에 남음",
      any("requests" in m and "발판" in m for m in rep.manual_suggestions))

print("\n=== _foothold_stage: degrade 시 조용히 종료(플래그/자격 변화 없음) ===")
orc2 = mk_orc()
rep2 = OrchestrationReport(target=TARGET, flag_kind="boot2root")
saved2 = sys.modules.get("htb_agent.shell_transport")
sys.modules["htb_agent.shell_transport"] = None
try:
    orc2._foothold_stage(rep2, mk_host())   # _acquire_session None → 조용히 반환
    ok = True
except Exception:                           # noqa: BLE001
    ok = False
finally:
    if saved2 is not None:
        sys.modules["htb_agent.shell_transport"] = saved2
    else:
        sys.modules.pop("htb_agent.shell_transport", None)
check("foothold_stage 도 크래시 없이 종료", ok)
check("발판 미확보 → 플래그 변화 없음", not orc2.world.flags)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
