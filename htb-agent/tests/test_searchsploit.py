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

# 회귀 가드: 요약기가 줄바꿈을 공백으로 합친 collapsed 출력도 항목을 정확히 분리해야 한다.
collapsed = ("Exploit Title | Path  FreePBX 13.0.188 - Remote Command Execution | "
             "php/remote/40434.rb  FreePBX 2.10 / 2.9 (Elastix) - RCE | php/webapps/18650.py")
ch = parse_searchsploit(collapsed)
check("collapsed 출력 2개로 분리", len(ch) == 2)
check("collapsed 제목에 헤더(Path) 안 섞임", ch[0].title == "FreePBX 13.0.188 - Remote Command Execution")
check("collapsed locator 정확", ch[0].locator == "php/remote/40434.rb" and ch[1].locator == "php/webapps/18650.py")
check("-w URL locator 파싱", parse_searchsploit("FreePBX | https://www.exploit-db.com/exploits/40434")[0].locator
      == "https://www.exploit-db.com/exploits/40434")

print("\n=== shortlist (버전 매칭) ===")
check("대상 13.0.188 → 그 익스가 1순위",
      shortlist(hits, "13.0.188")[0].versions == ["13.0.188"])
check("접두 호환(13.0 대상 ↔ 13.0.188 제목)",
      shortlist([SploitHit("x", "p", ["13.0.188"])], "13.0")[0].title == "x")
check("버전 미상 → 상위 N 그대로", len(shortlist(hits, "", limit=2)) == 2)
check("빈 입력 안전", shortlist([], "1.0") == [])
check("상한 적용", len(shortlist(hits, "", limit=1)) == 1)

print("\n=== summarize_tool_output: searchsploit 행 보존(200자 트렁케이트 회귀 가드) ===")
from htb_agent.observation.summarize import summarize_tool_output  # noqa: E402
# 기본 폴백은 200자 컷 → 익스 행(제목|경로)이 날아가 후보 추출 불가였다. 전용 요약이 쌍 보존.
raw = ("---------- ----------\n Exploit Title | Path\n---------- ----------\n"
       " FreePBX 2.10.0 / 2.9.0 (Elastix) - Remote Command Execution | php/webapps/18650.py\n"
       " FreePBX 13.0.188 - Remote Command Execution (Metasploit) | php/remote/40434.rb\n"
       " Sangoma FreePBX 14/15 - Authentication Bypass | php/webapps/48523.txt\n"
       " Some Other Long Title To Push Past Two Hundred Chars Easily Here Now | php/webapps/99999.py")
summ = summarize_tool_output("searchsploit freepbx", raw)
check("searchsploit 요약이 '제목|경로' 쌍 보존", "40434.rb" in summ and "48523.txt" in summ)
check("요약이 200자 트렁케이트 아님(폴백 회피)", "searchsploit:" in summ)
check("요약을 재파싱하면 후보 복원", len(parse_searchsploit(summ)) >= 4)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
