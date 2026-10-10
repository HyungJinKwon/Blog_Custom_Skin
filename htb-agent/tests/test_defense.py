# 실행: htb-agent 디렉토리에서  python3 tests/test_defense.py
#
# D. 공격↔방어 미러 — 식별·공략한 취약점(CVE/CWE/vuln매칭/웹앱)마다 탐지·완화를 짝지어 생성.
# ARTEX 의 공격↔방어 미러 문서 아이디어를 클린룸 재구현한 것의 검증(생성 전용).
import sys
sys.path.insert(0, "src")
from dataclasses import dataclass, field  # noqa: E402
from htb_agent import defense  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

@dataclass
class FakeMatch:
    name: str = ""
    cve: list = field(default_factory=list)
    cwe: list = field(default_factory=list)
    severity: str = "medium"
    note: str = ""

@dataclass
class FakeWorld:
    web_product: str = ""

@dataclass
class FakeReport:
    detected_cwe: list = field(default_factory=list)
    vuln_matches: list = field(default_factory=list)
    world: object = None

print("=== defense_items (근거 기반 생성) ===")
# CWE 기반
r1 = FakeReport(detected_cwe=["CWE-89", "CWE-78"])
items1 = defense.defense_items(r1)
labels1 = {i.vuln for i in items1}
check("CWE-89 방어 항목 생성", "CWE-89" in labels1)
check("CWE-78 방어 항목 생성", "CWE-78" in labels1)
check("각 항목에 탐지·완화 모두 존재", all(i.detect and i.remediate for i in items1))

# 기법 키워드(이름)에서 추론
r2 = FakeReport(vuln_matches=[FakeMatch(name="OpenSSH 사용자 열거", cwe=["CWE-200"])])
items2 = defense.defense_items(r2)
check("매칭 CWE-200 반영", any("CWE-200" in i.vuln or "200" in i.vuln for i in items2))

# 웹앱 제품 → n-day 노출 1건
r3 = FakeReport(world=FakeWorld(web_product="freepbx"))
items3 = defense.defense_items(r3)
check("웹앱 제품 식별 시 n-day 항목", any("freepbx" in i.vuln.lower() for i in items3))

# 근거 없으면 빈 목록(지어내지 않음)
check("근거 없으면 빈 목록", defense.defense_items(FakeReport()) == [])

# 중복 제거(같은 CWE 두 번)
r4 = FakeReport(detected_cwe=["CWE-89", "CWE-89"])
check("같은 CWE 중복 제거", len(defense.defense_items(r4)) == 1)

print("\n=== render_markdown ===")
md = defense.render_markdown(r1)
check("표 헤더 포함", "| 취약점/기법 | 탐지(Blue Team) | 완화(Remediation) |" in md)
check("CWE 행 렌더", "CWE-89" in md and "CWE-78" in md)
check("근거 없으면 정직한 안내", "생략" in defense.render_markdown(FakeReport()))
check("파이프 이스케이프(표 깨짐 방지)", "|" in md and "\n" in md)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
