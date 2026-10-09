# 실행: htb-agent 디렉토리에서  python3 tests/test_security_selfreview.py
# 보안 자가검수(2026-10)에서 재현으로 확인한 fail-open 결함 회귀 테스트.
#   FINDING 1 (HIGH): 파괴적 rm(루트/홈 재귀 삭제)이 철자·순서·분리 우회로 검증을 통과 →
#                     --auto --sandbox none 에서 운영 호스트에 자동 실행될 수 있었음.
#   FINDING 2 (MED) : VM --vm-confine 가 iptables-restore --noflush 로 적용돼, 기존 OUTPUT
#                     ACCEPT 규칙이 남아 있으면 정책이 DROP 이어도 송신이 열린 채 contained=True.
import re
import sys
sys.path.insert(0, "src")
from htb_agent.command_validator import validate  # noqa: E402
from htb_agent.tools.sandbox import _norm_cidrs  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== FINDING 1. 파괴적 rm/블록디바이스/포크폭탄 차단(정규식 우회 포함) ===")
BLOCK = [
    "rm -rf /",
    "rm -fr /",
    "rm -r -f /",
    "rm -f -r /",
    "rm --recursive --force /",
    "rm -rf /*",
    "rm -rf ~",
    "rm -rf $HOME",
    "sudo rm -fr /",
    "env X=1 rm -Rf /",
    "rm -rf --no-preserve-root /",
    "tee /dev/sda < x",
    "cp foo /dev/nvme0n1",
    "dd if=/dev/zero of=/dev/sda",
    "b(){ b|b& };b",
]
for c in BLOCK:
    rep = validate(c)
    check(f"차단: {c}", (not rep.ok) and any(i.code == "DESTRUCTIVE" for i in rep.errors))

print("\n=== FINDING 1(대조). 정상 재귀 삭제는 오탐 없이 통과 ===")
ALLOW = [
    "rm -rf ./loot",
    "rm -rf /work/tmp",
    "rm -rf tmp/scan",
    "rm -f report.txt",
    "rm -rf ../out",
    "rm -rf /tmp/htb-agent-xyz",
]
for c in ALLOW:
    rep = validate(c)
    check(f"허용: {c}", not any(i.code == "DESTRUCTIVE" for i in rep.errors))


# FINDING 2: VM OUTPUT 체인 ACCEPT 규칙 안전성 검사를 _apply_policy 에서 떼어낸 순수 로직으로
# 재현한다(원격 SSH·sudo 의존 없이). 구현과 동일한 규칙: lo·ESTABLISHED·허용대역(-d) 외의
# ACCEPT 가 하나라도 있으면 fail-open 이다.
def output_chain_is_safe(out_rules: str, allow_cidrs) -> bool:
    if "-P OUTPUT DROP" not in out_rules:
        return False
    allowed = set(_norm_cidrs(allow_cidrs))
    for raw in out_rules.splitlines():
        line = raw.strip()
        if not (line.startswith("-A OUTPUT") and line.endswith("-j ACCEPT")):
            continue
        if " -o lo " in f" {line} " or "ESTABLISHED" in line:
            continue
        m = re.search(r"-d (\S+)", line)
        if m:
            try:
                import ipaddress
                if str(ipaddress.ip_network(m.group(1), strict=False)) in allowed:
                    continue
            except ValueError:
                pass
        return False
    return True

print("\n=== FINDING 2. VM egress: 기존 광범위 ACCEPT 가 남은 체인은 fail-open 으로 거부 ===")
SAFE = ("-P OUTPUT DROP\n"
        "-A OUTPUT -o lo -j ACCEPT\n"
        "-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
        "-A OUTPUT -d 10.10.10.0/24 -j ACCEPT\n")
# --noflush 로 기존 전면 ACCEPT 가 우리 규칙 앞에 남은 상태
OPEN_ANY = ("-P OUTPUT DROP\n"
            "-A OUTPUT -j ACCEPT\n"
            "-A OUTPUT -o lo -j ACCEPT\n"
            "-A OUTPUT -d 10.10.10.0/24 -j ACCEPT\n")
# 허용대역 밖 목적지로의 기존 ACCEPT(예: DNS/업데이트 서버)
OPEN_OUT = ("-P OUTPUT DROP\n"
            "-A OUTPUT -o lo -j ACCEPT\n"
            "-A OUTPUT -d 8.8.8.8/32 -j ACCEPT\n"
            "-A OUTPUT -d 10.10.10.0/24 -j ACCEPT\n")
# 포트 한정이지만 목적지 무제한인 기존 ACCEPT
OPEN_PORT = ("-P OUTPUT DROP\n"
             "-A OUTPUT -p udp --dport 53 -j ACCEPT\n"
             "-A OUTPUT -d 10.10.10.0/24 -j ACCEPT\n")
NO_DROP = ("-P OUTPUT ACCEPT\n"
           "-A OUTPUT -d 10.10.10.0/24 -j ACCEPT\n")

check("안전한 체인(lo·established·허용대역)은 통과", output_chain_is_safe(SAFE, ["10.10.10.0/24"]))
check("전면 ACCEPT 잔존 → 거부", not output_chain_is_safe(OPEN_ANY, ["10.10.10.0/24"]))
check("허용대역 밖 목적지 ACCEPT 잔존 → 거부", not output_chain_is_safe(OPEN_OUT, ["10.10.10.0/24"]))
check("목적지 무제한 포트 ACCEPT 잔존 → 거부", not output_chain_is_safe(OPEN_PORT, ["10.10.10.0/24"]))
check("OUTPUT 기본 DROP 아님 → 거부", not output_chain_is_safe(NO_DROP, ["10.10.10.0/24"]))
check("호스트(/32) 허용대역도 -d 매칭", output_chain_is_safe(
    "-P OUTPUT DROP\n-A OUTPUT -d 10.129.5.5/32 -j ACCEPT\n", ["10.129.5.5"]))

print("\n=== FINDING A. rm 외 파괴적 바이너리 차단(디바이스/시스템 경로 한정) ===")
A_BLOCK = [
    "shred -u /etc/passwd", "shred -n 3 -z /dev/sda", "wipefs -a /dev/sda",
    "find / -delete", "find /home -type f -delete", "find /boot -delete",
    "find / -exec rm -rf {} ;", "chmod -R 000 /", "chmod --recursive 777 ~",
    "chown -R nobody:nobody /", "mke2fs /dev/sda1", "mkfs.ext4 /dev/sda1",
    "mkswap /dev/sda2", "dd if=/dev/zero of=/dev/loop0",
    "dd of=/dev/disk/by-id/foo if=/dev/zero", "dd if=/dev/null of=/etc/passwd",
    "truncate -s 0 /etc/shadow", ": > /etc/passwd", "cat /dev/null > /etc/passwd",
    "sudo wipefs -a /dev/nvme0n1", "tee /dev/mapper/x",
]
for c in A_BLOCK:
    rep = validate(c)
    check(f"차단: {c}", (not rep.ok) and any(i.code == "DESTRUCTIVE" for i in rep.errors))

print("\n=== FINDING A(대조). 정상 디스크/파일 작업은 오탐 없이 통과 ===")
A_ALLOW = [
    "shred ./creds.txt", "mkfs.ext4 disk.img", "dd if=/dev/zero of=out.img bs=1M count=10",
    "dd if=/dev/sda of=disk.img", "truncate -s 100M sparse.img", "find / -name flag.txt",
    "find . -type f -delete", "chmod -R 755 ./www", "chown -R user:user /home/user/app",
    "cp /dev/null ./empty", "find /var/www -name config.php", "echo data > ./out.txt",
]
for c in A_ALLOW:
    rep = validate(c)
    check(f"허용: {c}", not any(i.code == "DESTRUCTIVE" for i in rep.errors))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
