# 실행: htb-agent 디렉토리에서  python3 tests/test_writeup_enrich.py
# 라이트업 품질 강화: 블루팀 포트맵 확장 · CVE 레퍼런스(NVD/PoC) 반영 · CWE 라벨 · 고급조합.
import sys
sys.path.insert(0, "src")
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.runner import FakeRunner, RunOutput
from htb_agent.tools.recon import auto_approve_in_scope
from htb_agent.knowledge import KnowledgeBase
from htb_agent.vuln import VulnKB
from htb_agent.orchestrator import Orchestrator
from htb_agent.writeup import generate_writeup, generate_tistory, _cwe_label, _enriched_refs
from htb_agent.enrich import CveInfo

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

# 새 블루맵 포트를 다수 포함: SMTP(25)·DNS(53)·SNMP(161)·NFS(2049)·MSSQL(1433)·MySQL(3306)·Redis(6379)
XML = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.129.2.20"/><ports>
<port protocol="tcp" portid="25"><state state="open"/><service name="smtp"/></port>
<port protocol="tcp" portid="53"><state state="open"/><service name="domain"/></port>
<port protocol="udp" portid="161"><state state="open"/><service name="snmp"/></port>
<port protocol="tcp" portid="2049"><state state="open"/><service name="nfs"/></port>
<port protocol="tcp" portid="1433"><state state="open"/><service name="ms-sql-s"/></port>
<port protocol="tcp" portid="3306"><state state="open"/><service name="mysql"/></port>
<port protocol="tcp" portid="6379"><state state="open"/><service name="redis"/></port>
</ports></host></nmaprun>"""

g = ScopeGuard.from_cidr_strings(); g.bind_target("10.129.2.20"); g.add_attacker_ip("10.10.14.9")
r = FakeRunner(lambda c: RunOutput(c, stdout=XML) if c.startswith("nmap") else RunOutput(c, stdout=""))
rep = Orchestrator(g, r, KnowledgeBase.load(), auto_approve_in_scope,
                   vuln_kb=VulnKB.load(), is_tool_available=lambda b: True).run()

print("=== 블루팀 포트맵 확장(신규 서비스 매핑) ===")
md = generate_writeup(rep, attacker_ip="10.10.14.9", machine_name="SvcBox")
tis = generate_tistory(rep, machine_name="SvcBox", attacker_ip="10.10.14.9")
for svc, token in [("SMTP", "VRFY"), ("DNS", "AXFR"), ("SNMP", "public"),
                   ("NFS", "no_root_squash"), ("MSSQL", "xp_cmdshell"),
                   ("MySQL", "UDF"), ("Redis", "CONFIG SET")]:
    check(f"{svc} 블루팀 지표 포함", token in md)

print("\n=== 고급 명령 조합 확장(Tistory §8) ===")
for token in ["snmpwalk", "redis-cli", "showmount", "mssqlclient", "mysql -h"]:
    check(f"조합 포함: {token}", token in tis)

print("\n=== CWE 라벨(이름 병기) ===")
check("CWE-78 라벨", _cwe_label("CWE-78") == "CWE-78(OS Command Injection)")
check("미등재 CWE 는 ID만", _cwe_label("CWE-99999") == "CWE-99999")

print("\n=== CVE 레퍼런스(NVD/PoC) 반영 ===")
# enriched 비었을 때: 안내 문구
check("enriched 없음 안내", "오프라인" in _enriched_refs(rep) or "미탐지" in _enriched_refs(rep))
# enriched 주입 후: NVD URL·CVSS·PoC·CWE 라벨 표기
rep.enriched = [CveInfo(
    id="CVE-2021-41773", description="Apache HTTP Server path traversal and RCE",
    cvss="7.5", severity="HIGH", cwe=["CWE-22"],
    references=["https://httpd.apache.org/security/vulnerabilities_24.html"],
    poc_repos=["https://github.com/example/poc-41773"], source="nvd")]
md2 = generate_writeup(rep, attacker_ip="10.10.14.9", machine_name="SvcBox")
tis2 = generate_tistory(rep, machine_name="SvcBox", attacker_ip="10.10.14.9")
check("HTB: NVD 상세 URL", "nvd.nist.gov/vuln/detail/CVE-2021-41773" in md2)
check("HTB: CVSS 표기", "CVSS 7.5" in md2)
check("HTB: PoC 링크", "poc-41773" in md2)
check("HTB: CWE 라벨(Path Traversal)", "Path Traversal" in md2)
check("HTB: 설명 포함", "path traversal" in md2.lower())
check("Tistory: NVD 상세 URL", "nvd.nist.gov/vuln/detail/CVE-2021-41773" in tis2)
check("Tistory: 레퍼런스 섹션", "7.1 CVE 레퍼런스" in tis2)
check("HTB: 레퍼런스 섹션", "3.1 CVE 레퍼런스" in md2)

print("\n=== 순수 Markdown 유지(§7 HTML 배제) ===")
check("HTML 태그 없음(writeup)", "<div" not in md2 and "<span" not in md2)
check("HTML 태그 없음(tistory)", "<div" not in tis2 and "<span" not in tis2)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
