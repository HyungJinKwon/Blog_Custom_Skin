# 실행: htb-agent 디렉토리에서  python3 tests/test_provenance.py
# 플래그 출처 검증(실행 트레이스 기반) — 공략 유래 vs 로컬/불명 구분, 사람 보고용.
import sys
sys.path.insert(0, "src")
from htb_agent import provenance as pv

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")


print("=== classify: 대상 상호작용 → 공략 유래 ===")
p = pv.classify("user", "HTB{x}", "curl http://t/flag", "access")
check("curl → exploit-derived", p.verdict == "exploit-derived")
p = pv.classify("root", "HTB{y}", "nxc smb t -u a -p b -x 'type root.txt'", "privesc")
check("nxc → exploit-derived", p.verdict == "exploit-derived")

print("\n=== classify: 로컬/지식 → local-derived ===")
p = pv.classify("user", "HTB{x}", "cat /home/u/user.txt")
check("cat → local-derived(사람 확인)", p.verdict == "local-derived" and "사람 확인" in p.label)
p = pv.classify("user", "HTB{x}", "echo done && cat loot")
check("echo(값 없음) → local-derived", p.verdict == "local-derived")

print("\n=== classify: 값이 명령 입력에 있음 → reasoning-only(CTF-Abacus) ===")
p = pv.classify("user", "HTB{x}", "echo HTB{x}")
check("echo <flag> → reasoning-only(지어냈을 수 있음)", p.verdict == "reasoning-only")
check("reasoning-only 는 genuine 아님", p.genuine is False)

print("\n=== classify: 외부/학습 자료 유래 → looked-up ===")
p = pv.classify("user", "HTB{x}", "curl http://t", in_external=True)
check("external → looked-up", p.verdict == "looked-up" and p.genuine is False)
p = pv.classify("user", "HTB{x}", "", in_external=True)
check("명령 없음+external → looked-up", p.verdict == "looked-up")

print("\n=== classify: 명령 없음 → 출처 불명 ===")
p = pv.classify("user", "HTB{x}", "")
check("빈 명령 → unverified", p.verdict == "unverified")

print("\n=== audit 집계 ===")
provs = [pv.classify("user", "a", "curl http://t"), pv.classify("root", "b", "cat x"),
         pv.classify("user", "c", "")]
a = pv.audit(provs)
check("verdict 별 집계", a.get("exploit-derived") == 1 and a.get("local-derived") == 1 and a.get("unverified") == 1)

print("\n=== 오케스트레이터 통합(트레이스 → 출처 기록) ===")
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.runner import FakeRunner, RunOutput
from htb_agent.tools.recon import auto_approve_in_scope
from htb_agent.knowledge import KnowledgeBase
from htb_agent.orchestrator import Orchestrator

XML = ('<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.129.1.5"/>'
       '<ports><port protocol="tcp" portid="80"><state state="open"/>'
       '<service name="http" product="Apache"/></port></ports></host></nmaprun>')
def guard():
    g = ScopeGuard.from_cidr_strings(); g.bind_target("10.129.1.5"); return g
def responder(c):
    if c.startswith("nmap"): return RunOutput(c, stdout=XML)
    if c.startswith("curl"): return RunOutput(c, stdout="HTTP/1.1 200 OK\r\n\r\nHTB{curl_exploit_flag}")
    return RunOutput(c, stdout="ok")
rep = Orchestrator(guard(), FakeRunner(responder), KnowledgeBase.load(),
                   auto_approve_in_scope, flag_kind="single", flag_prefixes=("HTB",),
                   is_tool_available=lambda b: True).run()
check("플래그 포착", any(f.value == "HTB{curl_exploit_flag}" for f in rep.flags))
check("출처 기록됨", len(rep.flag_provenance) >= 1)
check("curl 유래 → exploit-derived",
      any(p.verdict == "exploit-derived" for p in rep.flag_provenance))
check("리포트에 PROVENANCE 섹션", "PROVENANCE" in rep.summary())

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
