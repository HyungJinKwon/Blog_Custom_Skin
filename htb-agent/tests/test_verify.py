# 실행: htb-agent 디렉토리에서  python3 tests/test_verify.py
#
# A. 적대적 재검증(skeptic) — 같은 값이 '독립 공략 명령'에서 재현됐는지로 확신도 채점.
# ARTEX retester("요청 한 번 실패 ≠ 해결", inconclusive 태도)의 클린룸 재구현 검증.
import sys
sys.path.insert(0, "src")
from htb_agent.verify import Confidence, assess, flag_format_ok, reread_commands  # noqa: E402
from htb_agent.provenance import FlagProvenance  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

HEX = "a" * 32
TAG = "HTB{r00ted_now}"

def P(kind, value, command, verdict):
    return FlagProvenance(kind=kind, value=value, command=command, verdict=verdict)

print("=== flag_format_ok ===")
check("32-hex 통과", flag_format_ok(HEX))
check("TAG{} 통과", flag_format_ok(TAG))
check("형식 불일치 거부", not flag_format_ok("not-a-flag"))
check("빈 값 거부", not flag_format_ok(""))

print("\n=== assess (확신도) ===")
# 서로 다른 공략 유래 명령 2개 → reproduced
c = assess("root", TAG, [
    P("root", TAG, "ssh user@t cat /root/root.txt", "exploit-derived"),
    P("root", TAG, "evil-winrm ... type root.txt", "exploit-derived"),
])
check("독립 2출처 → reproduced", c.level == "reproduced" and c.rank == 3)
check("sources 2개 기록", len(c.sources) == 2)

# 같은 명령(공백만 다름) 2번 → 독립 아님 → single-source
c2 = assess("user", HEX, [
    P("user", HEX, "cat  /home/u/user.txt", "exploit-derived"),
    P("user", HEX, "cat /home/u/user.txt", "exploit-derived"),
])
check("같은 명령 중복은 단일 출처로 합침", c2.level == "single-source")

# 공략 1 → single-source
c3 = assess("user", HEX, [P("user", HEX, "curl http://t/user.txt", "exploit-derived")])
check("공략 1개 → single-source", c3.level == "single-source")

# 로컬/외부만 → untrusted
c4 = assess("user", HEX, [P("user", HEX, "echo " + HEX, "reasoning-only"),
                          P("user", HEX, "cat notes.md", "looked-up")])
check("로컬/외부만 → untrusted", c4.level == "untrusted")

# 형식 불일치 → inconclusive(공략 출처 있어도)
c5 = assess("user", "garbage", [P("user", "garbage", "curl http://t/x", "exploit-derived")])
check("형식 불일치 → inconclusive", c5.level == "inconclusive")

# 출처 없음 → inconclusive
check("출처 없음 → inconclusive", assess("user", HEX, []).level == "inconclusive")
check("label 한국어", "재현" in assess("root", TAG, [
    P("root", TAG, "ssh a cat /root/root.txt", "exploit-derived"),
    P("root", TAG, "nc ... root.txt", "exploit-derived")]).label)

print("\n=== reread_commands (독립 재읽기 생성 — 생성 전용) ===")
rc = reread_commands("cat /root/root.txt")
check("cat 원본 → cat 아닌 리더 제시", rc and all(not c.startswith("cat ") for c in rc))
check("같은 경로 재사용", all("/root/root.txt" in c for c in rc))
check("최대 2개", len(rc) <= 2)
check("경로 없으면 빈 목록(억지 추측 안 함)", reread_commands("id; whoami") == [])
check("생성 문자열엔 실행/주입 없음", all(";" not in c and "&&" not in c for c in rc))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
