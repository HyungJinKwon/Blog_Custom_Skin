# 실행: htb-agent 디렉토리에서  python3 tests/test_enum_breadth.py
# 열거 서비스별 균등(round-robin): 작은 예산에서 한 서비스가 독식하지 않고 여러 서비스를 돈다.
import sys
sys.path.insert(0, "src")
from htb_agent.knowledge import KnowledgeBase, Rule
from htb_agent.orchestrator import Orchestrator
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.recon import auto_approve_in_scope
from htb_agent.tools.runner import FakeRunner, RunOutput
from htb_agent.observation.parsers import NmapHost, Port
from htb_agent.observation.compressor import profile_from_nmap

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

T = "10.129.1.5"
# web(5개)·smb(2개)·ftp(2개) 서비스 규칙 — web 이 많아 예산을 독식하기 쉬운 상황
kb = KnowledgeBase(rules=[
    Rule("web1", [f"curl -s http://{{t}}/a{i}" for i in range(5)], ports=[80], services=["http"], tags=["web"], phase="enum"),
    Rule("smb1", ["smbclient -NL //{t}", "smbmap -H {t}"], ports=[445], services=["microsoft-ds"], tags=["smb"], phase="enum"),
    Rule("ftp1", ["curl -s ftp://{t}/", "nmap --script ftp-anon {t}"], ports=[21], services=["ftp"], tags=["ftp"], phase="enum"),
], notes=[])

host = NmapHost(address=T, state="up", ports=[
    Port(80, "tcp", "open", "http"), Port(445, "tcp", "open", "microsoft-ds"),
    Port(21, "tcp", "open", "ftp")])
prof = profile_from_nmap(host)

ran = []
def resp(cmd):
    ran.append(cmd)
    return RunOutput(cmd, stdout="ok")

def guard():
    g = ScopeGuard.from_cidr_strings(); g.bind_target(T); return g

print("=== 작은 예산(3)에서 서비스가 고르게 ===")
orc = Orchestrator(guard(), FakeRunner(resp), kb, auto_approve_in_scope,
                   is_tool_available=lambda b: True, max_variants=1,
                   max_enum=3, max_rounds=1, max_sweeps=1)
# enum 라운드만 직접 호출
from htb_agent.orchestrator import OrchestrationReport
rep = OrchestrationReport(target=T)
from htb_agent.world import WorldModel
rep.world = orc.world = WorldModel(target=T)
n = orc._enum_round(rep, host, prof, T, set(), budget=3, phase="enum")
svc = set()
for c in ran:
    if "http" in c: svc.add("web")
    elif "smb" in c: svc.add("smb")
    elif "ftp" in c: svc.add("ftp")
check("예산 3 → 3개 실행", len([f for f in rep.enum_findings if f.ran]) == 3)
check("세 서비스 모두 한 번씩(독식 안 함)", svc == {"web", "smb", "ftp"})

print("\n=== 단일 서비스면 기존 순서(web 만) ===")
ran.clear()
kb2 = KnowledgeBase(rules=[Rule("web", [f"curl -s http://{{t}}/a{i}" for i in range(4)],
                                ports=[80], services=["http"], tags=["web"], phase="enum")], notes=[])
orc2 = Orchestrator(guard(), FakeRunner(resp), kb2, auto_approve_in_scope,
                    is_tool_available=lambda b: True, max_variants=1)
rep2 = OrchestrationReport(target=T); rep2.world = orc2.world = WorldModel(target=T)
orc2._enum_round(rep2, host, prof, T, set(), budget=2, phase="enum")
check("단일 서비스는 입력 순서대로", ran[:2] == ["curl -s http://10.129.1.5/a0",
                                           "curl -s http://10.129.1.5/a1"])

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
