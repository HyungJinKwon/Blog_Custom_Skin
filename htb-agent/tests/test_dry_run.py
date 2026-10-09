# 실행: htb-agent 디렉토리에서  python3 tests/test_dry_run.py
# --dry-run(계획 미리보기): 정찰은 하되 제안 명령은 '실행하지 않고' 보여만 준다.
import sys
sys.path.insert(0, "src")
from htb_agent.knowledge import KnowledgeBase
from htb_agent.llm.fake_provider import FakeProvider
from htb_agent.llm.router import LLMRouter
from htb_agent.orchestrator import Orchestrator
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.recon import auto_approve_in_scope
from htb_agent.tools.runner import FakeRunner, RunOutput

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

LINUX_WEB = ('<?xml version="1.0"?><nmaprun><host><status state="up"/>'
             '<address addr="10.129.1.5"/><ports>'
             '<port protocol="tcp" portid="80"><state state="open"/>'
             '<service name="http" product="Apache"/></port>'
             '</ports></host></nmaprun>')

def guard():
    g = ScopeGuard.from_cidr_strings(); g.bind_target("10.129.1.5"); return g

ALL = lambda b: True

def make_runner():
    ran = []
    def responder(cmd):
        ran.append(cmd)
        if cmd.startswith("nmap"):
            return RunOutput(cmd, stdout=LINUX_WEB)
        return RunOutput(cmd, stdout="ok-output")
    return FakeRunner(responder), ran

CMD = "ffuf -u http://{t}/FUZZ -w /tmp/w.txt"

print("=== dry-run: 제안 명령은 실행하지 않음 ===")
r, ran = make_runner()
orc = Orchestrator(guard(), r, KnowledgeBase.load(), auto_approve_in_scope,
                   llm_router=LLMRouter(FakeProvider(CMD)), is_tool_available=ALL,
                   dry_run=True)
rep = orc.run()
all_find = rep.enum_findings + rep.llm_findings
check("정상 종료", rep.status in ("done", "escalate"))
check("제안 명령은 러너로 실행되지 않음(ffuf 미실행)", not any("ffuf" in c for c in ran))
check("dry-run 비고로 표시된 제안 존재", any("dry-run" in (f.note or "") for f in all_find))
check("제안 finding 은 미실행(ran=False)",
      all(not f.ran for f in all_find if "dry-run" in (f.note or "")))
check("gate_stats.dry_run 집계", rep.gate_stats.get("dry_run", 0) >= 1)

print("\n=== 대조: dry-run 아니면 실제 실행 ===")
r2, ran2 = make_runner()
orc2 = Orchestrator(guard(), r2, KnowledgeBase.load(), auto_approve_in_scope,
                    llm_router=LLMRouter(FakeProvider(CMD)), is_tool_available=ALL)
orc2.run()
check("일반 모드에선 제안 명령 실행됨(ffuf 실행)", any("ffuf" in c for c in ran2))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
