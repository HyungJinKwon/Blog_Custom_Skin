# 실행: htb-agent 디렉토리에서  python3 tests/test_privesc.py
# 권한상승 플레이북 생성기 + CLI.
import io
import sys
from contextlib import redirect_stdout
sys.path.insert(0, "src")
from htb_agent import ui, privesc
from htb_agent.main import build_parser, main

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

ui.set_color_enabled(False)

print("=== build: Linux ===")
p = privesc.build("linux", "10.10.14.5")
check("단계 다수(>=10)", len(p.steps) >= 10)
check("os_class=linux", p.os_class == "linux")
check("sudo -l 열거", any("sudo -l" in s.command for s in p.steps))
check("SUID find", any("-perm -4000" in s.command for s in p.steps))
check("capabilities getcap", any("getcap -r" in s.command for s in p.steps))
check("LinPEAS 자동도구", any(s.category == "자동도구" for s in p.steps))
check("공격자 IP 반영(wget)", any("10.10.14.5" in s.command for s in p.steps))

print("\n=== build: Windows / AD ===")
pw = privesc.build("windows")
check("Windows 단계", len(pw.steps) >= 6)
check("whoami /priv", any("whoami /priv" in s.command for s in pw.steps))
check("AlwaysInstallElevated", any("AlwaysInstallElevated" in s.command for s in pw.steps))
pad = privesc.build("windows_ad")
check("AD 추가 단계", any(s.category == "AD" for s in pad.steps))
check("일반 Windows 엔 AD 단계 없음", not any(s.category == "AD" for s in pw.steps))

print("\n=== build: unknown → 빈 플랜 ===")
check("unknown 빈 steps", privesc.build("unknown").steps == [])
check("빈 문자열 빈 steps", privesc.build("").steps == [])

print("\n=== 커널 LPE 후보 매핑 ===")
check("DirtyPipe(5.13)", any("CVE-2022-0847" in c for c in privesc.kernel_exploit_candidates("5.13.0-30")))
check("DirtyCOW(3.10)", any("CVE-2016-5195" in c for c in privesc.kernel_exploit_candidates("3.10.0")))
check("최신 커널 후보 없음(6.5)", privesc.kernel_exploit_candidates("6.5.0-generic") == [])
check("버전 없음 → 빈", privesc.kernel_exploit_candidates("no-version-here") == [])

print("\n=== 탐지 CVE → LPE 후보 승격 ===")
pc = privesc.build("linux", "", ["CVE-2021-4034", "CVE-2019-0001"])
check("PwnKit 후보 승격", any("CVE-2021-4034" in c for c in pc.cve_candidates))
check("비-LPE CVE 는 제외", not any("CVE-2019-0001" in c for c in pc.cve_candidates))

print("\n=== --privesc CLI ===")
pp = build_parser()
a = pp.parse_args(["--privesc", "linux"])
check("--privesc 파싱(target 선택적)", a.privesc == "linux" and a.target is None)
check("OS choices 강제", True)
buf = io.StringIO()
with redirect_stdout(buf):
    code = main(["--privesc", "linux"])
out = buf.getvalue()
check("종료코드 0", code == 0)
check("SUID 출력", "-perm -4000" in out)
check("실행 안 함 명시", "실행" in out)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
