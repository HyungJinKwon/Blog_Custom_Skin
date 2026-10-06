# 실행: htb-agent 디렉토리에서  python3 tests/test_audit.py
import sys, tempfile, os, json
sys.path.insert(0, "src")
from htb_agent.audit import AuditLog, NullAudit
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

def read_events(path):
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out

print("=== AuditLog 기본 ===")
with tempfile.TemporaryDirectory() as d:
    a = AuditLog(os.path.join(d, "sub", "a.jsonl"))   # 디렉토리 자동생성
    a.event("test", x=1)
    a.event("exec", cmd="nmap")
    evs = read_events(a.path)
    check("디렉토리 자동 생성 + 기록", len(evs) == 2)
    check("ts/event 필드", all("ts" in e and "event" in e for e in evs))
    check("데이터 보존", evs[0]["x"] == 1 and evs[1]["cmd"] == "nmap")

print("\n=== NullAudit no-op ===")
n = NullAudit(); n.event("x", a=1); n.close()
check("NullAudit 예외 없음", True)

LINUX = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.129.1.5"/><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache"/></port>
</ports></host></nmaprun>"""
def guard():
    g = ScopeGuard.from_cidr_strings(); g.bind_target("10.129.1.5"); return g
def runner():
    return FakeRunner(lambda c: RunOutput(c, stdout=LINUX) if c.startswith("nmap") else RunOutput(c, stdout="ok"))

print("\n=== 오케스트레이터 트랜스크립트 ===")
with tempfile.TemporaryDirectory() as d:
    a = AuditLog(os.path.join(d, "run.jsonl"))
    Orchestrator(guard(), runner(), KnowledgeBase.load(), auto_approve_in_scope,
                 audit=a, is_tool_available=lambda b: True).run()
    evs = read_events(a.path)
    types = [e["event"] for e in evs]
    check("session_start 기록", "session_start" in types)
    check("recon 기록", "recon" in types)
    check("profile 기록", "profile" in types)
    check("proposed 기록", "proposed" in types)
    check("executed 기록", "executed" in types)
    check("vuln 기록", "vuln" in types)
    check("session_end 기록", "session_end" in types)
    # 실행 이벤트에 returncode/summary
    execs = [e for e in evs if e["event"] == "executed" and e.get("launched")]
    check("executed 에 summary", execs and "summary" in execs[0])

print("\n=== 동시 기록 스레드 안전(락) ===")
# 워커 스레드들이 event() 를 동시에 호출해도 JSONL 라인이 섞이지 않아야 한다.
import threading
with tempfile.TemporaryDirectory() as d:
    a = AuditLog(os.path.join(d, "concurrent.jsonl"))
    N_THREADS, PER = 16, 50

    def worker(tid):
        for i in range(PER):
            a.event("run_exception", tid=tid, i=i, cmd=f"tool-{tid}-{i}")

    ths = [threading.Thread(target=worker, args=(t,)) for t in range(N_THREADS)]
    for t in ths: t.start()
    for t in ths: t.join()
    # 모든 라인이 손상 없이 파싱되고(개수 일치), 라인 섞임이 없어야 한다.
    evs = read_events(a.path)
    check("동시 기록 유실/손상 없음(개수 일치)", len(evs) == N_THREADS * PER)
    check("모든 라인 정상 JSON 파싱", all(e.get("event") == "run_exception" for e in evs))
    seen = {(e["tid"], e["i"]) for e in evs}
    check("중복/누락 없이 전수 기록", len(seen) == N_THREADS * PER)

print("\n=== 승인 거부 기록 ===")
with tempfile.TemporaryDirectory() as d:
    a = AuditLog(os.path.join(d, "deny.jsonl"))
    # RECON(nmap)은 승인하고 enum 명령만 거부 → denied 이벤트 유도
    deny_enum = lambda cmd, v, s: cmd.startswith("nmap")
    Orchestrator(guard(), runner(), KnowledgeBase.load(), deny_enum,
                 audit=a, is_tool_available=lambda b: True).run()
    types = [e["event"] for e in read_events(a.path)]
    check("denied 기록", "denied" in types)
    check("미승인 시 executed 없음", "executed" not in types)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
