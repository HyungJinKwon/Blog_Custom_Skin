# 실행: htb-agent 디렉토리에서  python3 tests/test_enum_parsers.py
import sys
sys.path.insert(0, "src")
from htb_agent.observation.web import (parse_gobuster, parse_ffuf, parse_ffuf_json,
                                       parse_feroxbuster)
from htb_agent.observation.smb import (parse_smbclient_shares, parse_smbmap, parse_nxc_smb)
from htb_agent.observation.summarize import summarize_tool_output

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== gobuster dir ===")
gob = """===============================================================
Gobuster v3.6
===============================================================
/admin                (Status: 301) [Size: 312] [--> http://x/admin/]
/index.html           (Status: 200) [Size: 10918]
/secret               (Status: 403) [Size: 277]
Progress: 4000 / 4001
"""
r = parse_gobuster(gob)
check("경로 3건 파싱", len(r.entries) == 3)
check("상태/리다이렉트 파싱", any(e.status == 301 and e.redirect.endswith("/admin/") for e in r.entries))
check("요약 출력", "gobuster: 3건" in r.summary())

print("\n=== gobuster vhost ===")
vh = """Found: admin.machine.htb (Status: 200) [Size: 1234]
Found: dev.machine.htb (Status: 302) [Size: 0]
"""
r = parse_gobuster(vh)
check("vhost 2건", len(r.entries) == 2 and any(e.name == "admin.machine.htb" for e in r.entries))

print("\n=== ffuf json/text ===")
fj = '{"results":[{"input":{"FUZZ":"admin"},"status":200,"length":1234,"url":"http://x/admin"},{"input":{"FUZZ":"login"},"status":302,"length":0}]}'
r = parse_ffuf_json(fj)
check("ffuf json 2건", len(r.entries) == 2 and r.entries[0].name == "admin")
ft = "admin                   [Status: 200, Size: 1234, Words: 10, Lines: 5]\nlogin  [Status: 302, Size: 0, Words: 1, Lines: 1]"
r = parse_ffuf(ft)
check("ffuf text 2건", len(r.entries) == 2)
check("ffuf 디스패처 json 인식", len(parse_ffuf(fj).entries) == 2)

print("\n=== feroxbuster ===")
fx = """200      GET       10l       20w      300c http://x/admin
403      GET        5l       10w      100c http://x/secret
"""
r = parse_feroxbuster(fx)
check("ferox 2건", len(r.entries) == 2 and r.entries[0].status == 200)

print("\n=== smbclient -L ===")
sc = """
	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	backups         Disk
	IPC$            IPC       Remote IPC
SMB1 disabled -- no workgroup available
"""
r = parse_smbclient_shares(sc)
check("공유 3건", len(r.shares) == 3)
check("타입/코멘트 파싱", any(s.name == "ADMIN$" and s.type == "Disk" and "Remote Admin" in s.comment for s in r.shares))
check("--- 구분선 제외", all(s.name != "---------" for s in r.shares))

print("\n=== smbmap ===")
sm = """[+] IP: 10.129.1.5:445	Name: machine.htb
	Disk                     Permissions	Comment
	----                     -----------	-------
	ADMIN$                   NO ACCESS	Remote Admin
	backups                  READ ONLY
	data                     READ, WRITE	shared
"""
r = parse_smbmap(sm)
check("smbmap 공유 3건", len(r.shares) == 3)
check("권한 파싱", any(s.name == "data" and "READ, WRITE" in s.access for s in r.shares))
check("호스트 info", r.info.get("name") == "machine.htb")

print("\n=== netexec(nxc) smb ===")
nx = "SMB         10.129.1.10     445    DC01             [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)"
r = parse_nxc_smb(nx)
check("OS 파싱", "Windows Server 2019" in r.info.get("os", ""))
check("domain 파싱", r.info.get("domain") == "corp.local")
check("signing 파싱", r.info.get("signing") == "True")

print("\n=== summarize 디스패처 ===")
check("gobuster 라우팅", "gobuster:" in summarize_tool_output("gobuster dir -u http://x", gob))
check("smbmap 라우팅", "공유" in summarize_tool_output("smbmap -H 10.129.1.5", sm))
check("nxc 라우팅", "domain=corp.local" in summarize_tool_output("nxc smb 10.129.1.10", nx))
check("미지원도구 폴백 트렁케이트", summarize_tool_output("someweirdtool", "x"*300).endswith("…"))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
