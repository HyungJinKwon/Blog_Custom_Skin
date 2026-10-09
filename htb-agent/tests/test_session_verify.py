# 실행: htb-agent 디렉토리에서  python3 tests/test_session_verify.py
#
# 발판 성립 검증(생성 전용) — run('id') 출력으로 진짜 셸/헛발판 판정. 순수 파싱.
import sys
sys.path.insert(0, "src")
from htb_agent.session_verify import looks_like_shell, verify_probe_command  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== looks_like_shell: 진짜 셸 ===")
check("id 출력(uid=0 root)", looks_like_shell("uid=0(root) gid=0(root) groups=0(root)"))
check("id 출력(www-data)", looks_like_shell("uid=33(www-data) gid=33(www-data)"))
check("whoami 한 줄", looks_like_shell("www-data\n"))
check("uname -a", looks_like_shell("Linux connected 5.4.0-91-generic #102 x86_64 GNU/Linux"))

print("\n=== looks_like_shell: 헛발판(웹페이지/빈 응답) ===")
check("FreePBX 로그인 HTML → 죽음",
      not looks_like_shell("<html><head><title>FreePBX Administration</title></head>"
                           "<form method=post>login</form></html>"))
check("일반 HTML → 죽음", not looks_like_shell("<!doctype html><html><body>hi</body></html>"))
check("빈 응답 → 죽음", not looks_like_shell(""))
check("공백만 → 죽음", not looks_like_shell("   \n  \t "))
check("관련 없는 평문 → 보수적 False", not looks_like_shell("Welcome to the dashboard"))

print("\n=== 혼합(HTML 안에 uid 가 끼어도 실행 신호 우선) ===")
check("HTML+uid 동시 → 셸로 인정(실행 흔적 우선)",
      looks_like_shell("<pre>uid=33(www-data) gid=33(www-data)</pre>"))

print("\n=== verify_probe_command ===")
check("프로브는 무해 id/uname", verify_probe_command() == "id; uname -a")

print("\n=== 생성 전용 경계(불변) 자기점검 ===")
import htb_agent.session_verify as sv  # noqa: E402
for mod in ("subprocess", "socket", "os", "requests"):
    check(f"실행/네트워크 모듈 미임포트: {mod!r}", not hasattr(sv, mod))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
