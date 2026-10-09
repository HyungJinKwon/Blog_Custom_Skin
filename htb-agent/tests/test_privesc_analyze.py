# 실행: htb-agent 디렉토리에서  python3 tests/test_privesc_analyze.py
#
# ③ 권한상승 폐루프 — 열거 출력 분석 → 벡터 랭킹 → 상승 계획 생성(생성 전용).
# 파싱·랭킹·제안 문자열 생성만(실행 없음). 폐루프의 '후보 선정' 단계.
import sys
sys.path.insert(0, "src")
from htb_agent.privesc_analyze import (                               # noqa: E402
    PrivescVector, analyze_capabilities, analyze_enum, analyze_sudo, analyze_suid,
    render_vectors)

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== analyze_sudo ===")
SUDO = """Matching Defaults entries for user on host:
    env_reset, mail_badpass

User user may run the following commands on host:
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/less
"""
v = analyze_sudo(SUDO)
kinds = {x.binary: x for x in v}
check("find 벡터 식별", "find" in kinds and kinds["find"].kind == "sudo")
check("find 상승 계획(GTFOBins)", "find" in kinds["find"].plan and "/bin/sh" in kinds["find"].plan)
check("NOPASSWD → 확신도 high", kinds["find"].confidence == "high")
check("less 벡터도 식별", "less" in kinds)
check("빈 입력 안전", analyze_sudo("") == [])

ALL_SUDO = "User x may run the following commands:\n    (ALL : ALL) ALL\n"
va = analyze_sudo(ALL_SUDO)
check("(ALL : ALL) ALL → sudo-all 최상위", any(x.kind == "sudo-all" for x in va))
check("sudo-all 계획 sudo -i", any("sudo -i" in x.plan for x in va))

print("\n=== analyze_suid ===")
SUID = """/usr/bin/sudo
/usr/bin/passwd
/usr/bin/find
/usr/bin/python3.8
/home/user/custombin
"""
s = analyze_suid(SUID)
sk = {x.binary: x for x in s}
check("SUID find 식별", "find" in sk and sk["find"].kind == "suid")
check("SUID find -p 보존 셸 계획", "-p" in sk["find"].plan)
check("표준 SUID(sudo/passwd) 제외", "sudo" not in sk and "passwd" not in sk)
check("매핑 없는 custombin 은 조용히 스킵", "custombin" not in sk)
check("빈 입력 안전", analyze_suid("") == [])

print("\n=== analyze_capabilities ===")
CAPS = """/usr/bin/python3.8 = cap_setuid+ep
/usr/bin/ping = cap_net_raw+ep
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+ep
"""
c = analyze_capabilities(CAPS)
ck = {x.binary: x for x in c}
check("cap_setuid python 식별", any("python" in x.binary for x in c))
check("python cap 계획 setuid(0)", any("setuid(0)" in x.plan for x in c))
check("cap_net_raw(ping) 는 setuid 아님 → 제외", not any("ping" in x.binary for x in c))
check("빈 입력 안전", analyze_capabilities("") == [])

print("\n=== analyze_enum (통합·랭킹) + render ===")
COMBINED = SUDO + "\n" + SUID + "\n" + CAPS
allv = analyze_enum(COMBINED)
check("여러 소스 벡터 통합", len(allv) >= 3)
check("확신도순 정렬(high 먼저)", allv[0].confidence == "high")
check("중복 제거(find sudo/suid 분리 유지)",
      len([x for x in allv if x.binary == "find"]) == 2)  # sudo+suid 는 다른 kind
r = render_vectors(allv)
check("render 에 제안 명령(↳) 포함", "↳" in r)
check("벡터 없으면 안내 문구", "후보 없음" in render_vectors([]))

print("\n=== 생성 전용 경계(불변) 자기점검 ===")
import htb_agent.privesc_analyze as pa  # noqa: E402
for mod in ("subprocess", "socket", "os", "requests", "urllib", "shutil", "pty"):
    check(f"실행/네트워크 모듈 미임포트: {mod!r}", not hasattr(pa, mod))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
