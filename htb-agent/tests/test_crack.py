# 실행: htb-agent 디렉토리에서  python3 tests/test_crack.py
# 해시 크래킹 생성기(John/hashcat) + CLI.
import io
import sys
from contextlib import redirect_stdout
sys.path.insert(0, "src")
from htb_agent import ui, crack
from htb_agent.main import build_parser, main

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

ui.set_color_enabled(False)

print("=== identify: 종류·모드 ===")
def mode(h):
    g = crack.identify(h)
    return g[0].hashcat_mode if g else None
check("Kerberoast TGS → 13100", mode("$krb5tgs$23$*u$R*$deadbeef") == "13100")
check("AS-REP → 18200", mode("$krb5asrep$23$u@R:aabb") == "18200")
check("md5crypt $1$ → 500", mode("$1$salt$abc") == "500")
check("sha256crypt $5$ → 7400", mode("$5$salt$abc") == "7400")
check("sha512crypt $6$ → 1800", mode("$6$salt$abc") == "1800")
check("bcrypt $2b$ → 3200", mode("$2b$12$abcdefghijklmnopqrstuv") == "3200")
check("NetNTLMv2 → 5600", mode("user::DOM:" + "a"*16 + ":" + "b"*32 + ":0011") == "5600")
check("MySQL *40hex → 300", mode("*" + "A"*40) == "300")
# 원시 해시 모호 → 후보 병기
g32 = crack.identify("a"*32)
check("32hex → NTLM+MD5 후보 2개", {x.hashcat_mode for x in g32} == {"1000", "0"})
check("40hex → SHA1(100)", mode("a"*40) == "100")
check("64hex → SHA256(1400)", mode("a"*64) == "1400")
check("빈 입력 → 빈 리스트", crack.identify("") == [])
check("미상 → 식별실패 1건", "식별 실패" in crack.identify("short")[0].name)

print("\n=== etype 별 Kerberoast 모드 ===")
check("TGS etype17 → 19600", mode("$krb5tgs$17$*u$R*$x") == "19600")
check("TGS etype18 → 19700", mode("$krb5tgs$18$*u$R*$x") == "19700")

print("\n=== scan_hashes: 고신뢰만 ===")
txt = ("log $krb5tgs$23$*svc$DOM*$abcd0011 then $6$aa$bb and "
       "user::DOM:" + "a"*16 + ":" + "b"*32 + ":cc end")
sc = crack.scan_hashes(txt)
check("TGS 추출", any(s.startswith("$krb5tgs$") for s in sc))
check("sha512crypt 추출", any(s.startswith("$6$") for s in sc))
check("NetNTLMv2 추출", any("::DOM:" in s for s in sc))
check("원시 hex 는 미추출(노이즈)", not any(len(s) == 32 and all(c in '0123456789abcdef' for c in s) for s in sc))
check("중복 없음", len(sc) == len(set(sc)))

print("\n=== commands: john+hashcat 생성 ===")
cs = crack.commands("$krb5tgs$23$x", hashfile="h.txt", wordlist="rock.txt")
check("hashcat -m 13100", any("hashcat -m 13100 h.txt rock.txt" == c.command for c in cs))
check("john --format=krb5tgs", any("--format=krb5tgs" in c.command for c in cs))
check("john 폴백 포함", any(c.name == "자동판별(폴백)" for c in cs))

print("\n=== prepare: 여러 해시·중복 제거 ===")
jobs = crack.prepare(["$6$a$b", "$6$a$b", "$krb5asrep$23$u:aa"])
check("중복 해시 1개로", len(jobs) == 2)
check("각 작업에 명령 존재", all(j.commands for j in jobs))

print("\n=== --crack CLI ===")
pp = build_parser()
a = pp.parse_args(["--crack", "$6$salt$h"])
check("--crack 파싱(target 선택적)", a.crack == "$6$salt$h" and a.target is None)
buf = io.StringIO()
with redirect_stdout(buf):
    code = main(["--crack", "$krb5tgs$23$*u$R*$abcd"])
out = buf.getvalue()
check("종료코드 0", code == 0)
check("hashcat 모드 출력", "13100" in out)
check("john 출력", "john" in out)
check("실행 안 함 명시", "실행" in out)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
