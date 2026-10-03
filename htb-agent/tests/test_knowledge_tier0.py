# 실행: htb-agent 디렉토리에서  python3 tests/test_knowledge_tier0.py
# 사용자 제공 학습데이터(HTB Starting Point Tier 0) 규칙 회귀 보호.
import os
import sys
sys.path.insert(0, "src")
from htb_agent.knowledge import KnowledgeBase
from htb_agent.command_validator import validate

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

KN = os.path.join(os.path.dirname(__file__), "..", "knowledge")
kb = KnowledgeBase.load(base_dir=KN)
tier0 = [r for r in kb.rules if r.source.startswith("user:htb-startingpoint")]

print("=== Tier0 학습데이터 로드 ===")
check("규칙 8개 로드", len(tier0) == 8)
check("노트 로드됨", any("Starting Point Tier 0" in n or "startingpoint" in n.lower()
                       for n in kb.notes))

print("\n=== 모든 제안 명령 검증(치환 후) ===")
bad = 0
for r in tier0:
    for tmpl in r.suggest:
        cmd, _auto = kb.format_suggestion(tmpl, "10.129.1.5")
        if not validate(cmd).ok:
            bad += 1
            print(f"    ! FAIL: {cmd}")
check("모든 명령 문법/형식 검증 통과", bad == 0)

print("\n=== 서비스→규칙 매칭 ===")
expect = {
    ("linux", 23, "telnet"): "Telnet",
    ("linux", 21, "ftp"): "FTP",
    ("windows", 445, "microsoft-ds"): "SMB",
    ("linux", 6379, "redis"): "Redis",
    ("linux", 27017, "mongodb"): "MongoDB",
    ("linux", 873, "rsync"): "rsync",
    ("windows", 3389, "ms-wbt-server"): "RDP",
}
for (osc, port, svc), kw in expect.items():
    recs = kb.query(osc, [port], [svc])
    names = " | ".join(r.rule_name for r in recs)
    check(f"{svc}:{port} → '{kw}' 규칙 제안", kw in names)

print("\n=== Tier I/II 학습데이터 로드/검증 ===")
t12 = [r for r in kb.rules if r.source.startswith("user:htb-tier1-2")]
check("Tier1-2 규칙 30개 로드", len(t12) == 30)
bad12 = 0
for r in t12:
    for tmpl in r.suggest:
        cmd, _ = kb.format_suggestion(tmpl, "10.129.1.5")
        if not validate(cmd).ok:
            bad12 += 1
            print(f"    ! FAIL: {cmd}")
check("Tier1-2 모든 명령 검증 통과", bad12 == 0)

expect12 = {
    ("windows", 1433, "ms-sql"): "MSSQL",
    ("linux", 69, "tftp"): "TFTP",
    ("windows", 5985, "winrm"): "evil-winrm",
    ("windows", 445, "microsoft-ds"): "psexec",
}
for (osc, port, svc), kw in expect12.items():
    recs = kb.query(osc, [port], [svc])
    names = " | ".join(r.rule_name for r in recs)
    check(f"{svc}:{port} → '{kw}' 규칙 제안", kw in names)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
