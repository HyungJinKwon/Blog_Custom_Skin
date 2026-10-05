# 실행: htb-agent 디렉토리에서  python3 tests/test_orchestrator.py
import sys
sys.path.insert(0, "src")
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.runner import FakeRunner, RunOutput
from htb_agent.tools.recon import auto_approve_in_scope
from htb_agent.knowledge import KnowledgeBase
from htb_agent.orchestrator import Orchestrator
from htb_agent.target_profiler import OSClass

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

LINUX_WEB = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.129.1.5"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.2 Ubuntu"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache"/></port>
</ports></host></nmaprun>"""
AD = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.129.1.10"/><ports>
<port protocol="tcp" portid="88"><state state="open"/><service name="kerberos-sec"/></port>
<port protocol="tcp" portid="389"><state state="open"/><service name="ldap"/></port>
<port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>
<port protocol="tcp" portid="5985"><state state="open"/><service name="winrm"/></port>
</ports><hostscript><script id="smb-os-discovery" output="OS: Windows Server 2019"/></hostscript>
</host></nmaprun>"""
DOWN = """<?xml version="1.0"?><nmaprun><host><status state="down"/><address addr="10.129.1.9"/></host></nmaprun>"""

def guard(ip="10.129.1.5"):
    g = ScopeGuard.from_cidr_strings(); g.bind_target(ip); return g

# nmap 은 포트결과, 그 외(enum 도구)는 간단한 출력
def responder(xml):
    def r(cmd):
        if cmd.startswith("nmap"):
            return RunOutput(cmd, stdout=xml)
        if cmd.startswith("curl"):
            return RunOutput(cmd, stdout="HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n<title>Home</title>")
        return RunOutput(cmd, stdout="enum-output-ok")
    return r

kb = KnowledgeBase.load()
ALL_TOOLS = lambda b: True   # 도구 전부 설치됐다고 가정(테스트)

print("=== Linux 웹 호스트 파이프라인 ===")
r = FakeRunner(responder(LINUX_WEB))
orc = Orchestrator(guard(), r, kb, auto_approve_in_scope, is_tool_available=ALL_TOOLS)
rep = orc.run()
check("상태 done", rep.status == "done")
check("프로파일 Linux", rep.profile.os_class == OSClass.LINUX)
check("enum 자동실행 발생", any(f.ran for f in rep.enum_findings))
check("curl HTTP 파싱요약", any("HTTP 200" in f.output for f in rep.enum_findings))

print("\n=== Windows-AD 파이프라인 + 수동제안 ===")
r = FakeRunner(responder(AD))
orc = Orchestrator(guard("10.129.1.10"), r, kb, auto_approve_in_scope, is_tool_available=ALL_TOOLS)
rep = orc.run()
check("프로파일 Windows-AD", rep.profile.os_class == OSClass.WINDOWS_AD)
check("BloodHound 등 수동제안 분류", any("bloodhound-python" in s for s in rep.manual_suggestions))
check("크리덴셜 명령 자동실행 안 됨",
      all("evil-winrm" not in f.command for f in rep.enum_findings))

print("\n=== enum 상한(무한확장 방지) ===")
r = FakeRunner(responder(LINUX_WEB))
orc = Orchestrator(guard(), r, kb, auto_approve_in_scope, max_enum=1, is_tool_available=ALL_TOOLS)
rep = orc.run()
ran = [f for f in rep.enum_findings if f.ran]
check("enum 자동실행 max_enum 준수", len(ran) <= 1)

print("\n=== 도구 미설치 → 건너뜀(무한재시도 없음) ===")
r = FakeRunner(responder(LINUX_WEB))
orc = Orchestrator(guard(), r, kb, auto_approve_in_scope, is_tool_available=lambda b: False)
rep = orc.run()
check("미설치 도구 건너뜀", any("미설치" in f.note for f in rep.enum_findings))
check("미설치 시 실행 안 함", all(not f.ran for f in rep.enum_findings))

print("\n=== 리버스쉘 자동 준비(공격자 IP 확보 시 · 생성만) ===")
g = guard()
g.add_attacker_ip("10.10.14.5")
r = FakeRunner(responder(LINUX_WEB))
orc = Orchestrator(g, r, kb, auto_approve_in_scope, is_tool_available=ALL_TOOLS,
                   revshell_port=9001)
rep = orc.run()
check("리버스쉘 자동 생성됨", len(rep.revshells) >= 10)
check("LHOST=공격자IP", rep.revshell_lhost == "10.10.14.5")
check("LPORT=지정포트", rep.revshell_lport == 9001)
check("bash 페이로드 치환", any("/dev/tcp/10.10.14.5/9001" in s.payload for s in rep.revshells))
check("자동 생성은 실행 아님(ran 플래그 무관)",
      all(hasattr(s, "payload") for s in rep.revshells))
check("summary 에 리버스쉘 노출", "리버스쉘" in rep.summary())

print("\n=== 공격자 IP 없으면 리버스쉘 생략 ===")
r = FakeRunner(responder(LINUX_WEB))
orc = Orchestrator(guard(), r, kb, auto_approve_in_scope, is_tool_available=ALL_TOOLS)
rep = orc.run()
check("공격자IP 없음 → 리버스쉘 없음", rep.revshells == [])

print("\n=== RECON 실패 → 에스컬레이션(enum 진입 안 함) ===")
r = FakeRunner(responder(DOWN))
orc = Orchestrator(guard("10.129.1.9"), r, kb, auto_approve_in_scope, is_tool_available=ALL_TOOLS)
rep = orc.run()
check("포트없음 → 에스컬레이션", rep.status == "escalate")
check("enum 미진입", len(rep.enum_findings) == 0)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
