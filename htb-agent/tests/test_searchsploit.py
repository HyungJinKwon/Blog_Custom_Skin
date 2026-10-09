# 실행: htb-agent 디렉토리에서  python3 tests/test_searchsploit.py
#
# searchsploit 출력 파서 + 버전 매칭 검증(생성 전용 — 파싱만, 실행 없음).
# 대상 버전에 맞는 PoC 를 앞세워 '선택지를 좁혀' 제시하는지 확인.
import sys
sys.path.insert(0, "src")
from htb_agent.searchsploit import parse_searchsploit, shortlist, SploitHit  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

OUT = """--------------------------------- ---------------------------------
 Exploit Title                    | Path
--------------------------------- ---------------------------------
 FreePBX 2.10.0 / 2.9.0 (Elastix) - Remote Command Execution | php/webapps/18650.py
 FreePBX 13.0.188 - Remote Command Execution (Metasploit)     | php/remote/40434.rb
 Sangoma FreePBX 14/15 - Authentication bypass                | php/webapps/48523.txt
--------------------------------- ---------------------------------"""

print("=== parse_searchsploit ===")
hits = parse_searchsploit(OUT)
check("데이터 행 3개 파싱", len(hits) == 3)
check("헤더·구분선 제외", all("Exploit Title" not in h.title for h in hits))
check("locator 추출", any(h.locator == "php/remote/40434.rb" for h in hits))
check("제목에서 버전 추출", any("13.0.188" in h.versions for h in hits))
check("빈 입력 안전", parse_searchsploit("") == [])
check("무결과 → 빈 목록", parse_searchsploit("Exploits: No Results") == [])

print("\n=== shortlist (버전 매칭) ===")
check("대상 13.0.188 → 그 익스가 1순위",
      shortlist(hits, "13.0.188")[0].versions == ["13.0.188"])
check("접두 호환(13.0 대상 ↔ 13.0.188 제목)",
      shortlist([SploitHit("x", "p", ["13.0.188"])], "13.0")[0].title == "x")
check("버전 미상 → 상위 N 그대로", len(shortlist(hits, "", limit=2)) == 2)
check("빈 입력 안전", shortlist([], "1.0") == [])
check("상한 적용", len(shortlist(hits, "", limit=1)) == 1)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
