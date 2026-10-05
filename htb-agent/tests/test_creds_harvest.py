# 실행: htb-agent 디렉토리에서  python3 tests/test_creds_harvest.py
# 크리덴셜 자동 수확 + 오케스트레이터 통합(월드/볼트 반영, 인젝션 차단).
import sys
sys.path.insert(0, "src")
from htb_agent import creds_harvest as ch
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.runner import FakeRunner, RunOutput
from htb_agent.tools.recon import auto_approve_in_scope
from htb_agent.knowledge import KnowledgeBase
from htb_agent.creds import CredentialVault
from htb_agent.orchestrator import Orchestrator

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== harvest: URL 자격 ===")
check("mysql URL", ch.harvest("mysql://admin:S3cret@10.0.0.1/db") == [("admin", "S3cret")])
check("ftp URL", ("bob", "pw123") in ch.harvest("ftp://bob:pw123@host"))
check("http URL 자격", ("u", "p") in ch.harvest("http://u:p@site/"))

print("\n=== harvest: key=value 쌍 ===")
check("username/password 쌍", ch.harvest("username: bob\npassword: hunter2") == [("bob", "hunter2")])
check("DB_USER/DB_PASS", ("svc", "sp") in ch.harvest("DB_USER=svc\nDB_PASSWORD=sp"))
check("여러 user → 모호해서 생략", ch.harvest("user=a\nuser=b\npassword=x") == [])
check("플레이스홀더 값 제외", ch.harvest("username=admin\npassword=changeme") == [])
check("빈 입력", ch.harvest("") == [])

print("\n=== is_safe_for_cmd (인젝션 차단) ===")
check("정상 값 안전", ch.is_safe_for_cmd("S3cret") and ch.is_safe_for_cmd("Pass123"))
check("세미콜론 거부", not ch.is_safe_for_cmd("p; id"))
check("백틱 거부", not ch.is_safe_for_cmd("a`whoami`"))
check("공백 거부", not ch.is_safe_for_cmd("a b"))
check("$() 거부", not ch.is_safe_for_cmd("x$(id)"))

print("\n=== 오케스트레이터 통합: 수확 → 월드/볼트 ===")
LINUX = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.129.1.5"/><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache"/></port>
</ports></host></nmaprun>"""
def guard():
    g = ScopeGuard.from_cidr_strings(); g.bind_target("10.129.1.5"); return g
# curl 출력에 연결 문자열 자격이 노출되는 상황
def resp(cmd):
    if cmd.startswith("nmap"):
        return RunOutput(cmd, stdout=LINUX)
    if cmd.startswith("curl"):
        return RunOutput(cmd, stdout="HTTP/1.1 200 OK\r\n\r\nDB=mysql://webapp:Pass123@db.local/app")
    return RunOutput(cmd, stdout="ok")
vault = CredentialVault()
orc = Orchestrator(guard(), FakeRunner(resp), KnowledgeBase.load(), auto_approve_in_scope,
                   is_tool_available=lambda b: True, vault=vault)
rep = orc.run()
check("월드에 수확 자격 반영", any("webapp:Pass123" in c for c in rep.world.creds))
check("권한레벨 credentialed 이상", rep.world.has_access("credentialed"))
check("안전 자격은 실행 볼트에 추가", any(c.username == "webapp" for c in vault.creds))

print("\n=== 인젝션 자격은 볼트 제외(월드만) ===")
def resp2(cmd):
    if cmd.startswith("nmap"):
        return RunOutput(cmd, stdout=LINUX)
    if cmd.startswith("curl"):
        # 셸 메타문자(|) 포함 비밀번호 → 수확은 되나 볼트 제외 대상
        return RunOutput(cmd, stdout="username: evil\npassword: p|id")
    return RunOutput(cmd, stdout="ok")
vault2 = CredentialVault()
orc2 = Orchestrator(guard(), FakeRunner(resp2), KnowledgeBase.load(), auto_approve_in_scope,
                    is_tool_available=lambda b: True, vault=vault2)
rep2 = orc2.run()
check("월드엔 반영", any("evil:p|id" in c for c in rep2.world.creds))
check("볼트엔 미추가(인젝션 차단)", not any(c.username == "evil" for c in vault2.creds))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
