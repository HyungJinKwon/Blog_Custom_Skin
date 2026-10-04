# 실행: htb-agent 디렉토리에서  python3 tests/test_knowledge_expansion.py
# 지식베이스 확장 검증: 공개 CVE 서비스팩 + Linux/Windows 권한상승 규칙 + CWE 테이블.
import sys
sys.path.insert(0, "src")
from htb_agent.vuln import VulnKB
from htb_agent.knowledge import KnowledgeBase
from htb_agent.enrich import CWE_NAMES

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== 공개 CVE 서비스팩(common-services) 매칭 ===")
vk = VulnKB.load("knowledge")
def match_names(banner):
    return {m.name for m in vk.match([banner], "10.10.10.10")}

check("Exim 4.90 → CVE-2019-10149", any("Exim" in n for n in match_names("Exim smtpd 4.90")))
check("Tomcat 9.0.30 → Ghostcat", any("Ghostcat" in n for n in match_names("Apache Tomcat 9.0.30")))
check("Tomcat 8.5.50 → Ghostcat", any("Ghostcat" in n for n in match_names("Apache Tomcat 8.5.50")))
check("Grafana 8.3.0 → 경로우회", any("Grafana" in n for n in match_names("Grafana 8.3.0")))
check("Jenkins(서비스명) → CVE-2024-23897", any("Jenkins" in n for n in match_names("Jetty Jenkins")))
check("Confluence → OGNL", any("Confluence" in n for n in match_names("Atlassian Confluence")))
check("PHP/5.3.29 → PHP-CGI", any("PHP-CGI" in n for n in match_names("PHP/5.3.29")))

print("\n=== 버전 경계: 무관 버전 오탐 없음 ===")
check("nginx 1.18 매칭 없음", match_names("nginx 1.18") == set())
check("Tomcat 6.0 (범위밖) 매칭 없음", not any("Ghostcat" in n for n in match_names("Apache Tomcat 6.0.53")))
check("Exim 4.92(패치) 매칭 없음", not any("Exim" in n for n in match_names("Exim smtpd 4.92")))

print("\n=== CVE 심각도 정렬(critical 우선) ===")
ms = vk.match(["Exim smtpd 4.90", "PHP/5.3.29"], "10.10.10.10")
check("critical 가 high 보다 앞", ms[0].severity == "critical")

print("\n=== Linux/Windows 권한상승 규칙 로드 ===")
kb = KnowledgeBase.load("knowledge")
lin = kb.query("linux", [22], ["ssh"], phase="privesc")
check("Linux privesc 규칙 존재", any("권한상승" in r.rule_name or "PwnKit" in r.rule_name for r in lin))
check("PwnKit 규칙 포함", any("PwnKit" in r.rule_name for r in lin))
win = kb.query("windows_ad", [88, 445], ["kerberos", "smb"], phase="privesc")
check("Windows/AD privesc 규칙 존재", len(win) > 0)
check("Kerberoasting 포함", any("Kerberoast" in r.rule_name for r in win))
lat = kb.query("windows_ad", [445], ["smb"], phase="lateral")
check("측면이동(DCSync/PtH) 포함",
      any("DCSync" in r.rule_name or "Pass-the-Hash" in r.rule_name for r in lat))

print("\n=== 권한상승 제안은 자동실행 아님(크리덴셜 플레이스홀더로 수동) ===")
# {user}/{pass} 등이 남으면 수동(auto_runnable=False)
auto_cmds = []
for r in lin:
    for tmpl in r.suggestions:
        cmd, auto = kb.format_suggestion(tmpl, "10.10.10.10")
        if auto: auto_cmds.append(cmd)
check("Linux privesc 전부 수동(자동실행 0)", auto_cmds == [])

print("\n=== CWE 테이블 확장(example.json 의 CWE-264 공백 해소) ===")
check("CWE-264 등재", CWE_NAMES.get("CWE-264") == "Permissions, Privileges, and Access Controls")
check("CWE-917 등재", CWE_NAMES.get("CWE-917") == "Expression Language Injection")
check("CWE-330 등재(Zerologon)", "Random" in CWE_NAMES.get("CWE-330", ""))
check("CWE-362 등재(Dirty COW)", "Race" in CWE_NAMES.get("CWE-362", ""))

print("\n=== 모든 vulns/*.json 의 CWE 가 테이블에 존재(라벨 공백 방지) ===")
import glob, json
missing = set()
for f in glob.glob("knowledge/vulns/*.json"):
    data = json.load(open(f, encoding="utf-8"))
    for it in (data if isinstance(data, list) else [data]):
        for c in it.get("cwe", []):
            if c and c not in CWE_NAMES:
                missing.add(c)
check(f"미등재 CWE 없음 (발견: {sorted(missing) or '없음'})", not missing)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
