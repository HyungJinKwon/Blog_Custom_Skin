# ASSASSIN 샌드박스 — 완전자율 실행용 Kali 컨테이너
# 빌드: ./scripts/build_sandbox.sh   (또는 docker build -t assassin-sandbox:latest sandbox/)
#
# 보안 모델
#  - 에이전트는 시작 직후 root 로 iptables egress 정책(기본 DROP, 타겟 /32 만 허용)을 적용한다.
#  - 명령은 비root 'agent' 사용자 + no-new-privileges 로 실행 → 정책 변경·권한 상승 불가.
#  - sudo 를 설치하지 않는다. 작업공간은 /work(호스트 state/work/<타겟> 마운트).
FROM kalilinux/kali-rolling

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates iptables iproute2 procps coreutils file binutils bsdextrautils \
        python3 python3-pip python3-venv python3-requests python3-pwntools python3-pycryptodome \
        nmap curl wget netcat-openbsd socat dnsutils whatweb nikto \
        ffuf gobuster feroxbuster seclists sqlmap \
        smbclient smbmap ldap-utils snmp ftp rsync redis-tools default-mysql-client postgresql-client \
        netexec impacket-scripts enum4linux-ng sshpass openssh-client \
        gdb radare2 ltrace strace patchelf \
        binwalk foremost exiftool steghide tshark \
        john hashcat \
    && rm -rf /var/lib/apt/lists/*

# 명령 실행 사용자(비root). egress 정책을 바꿀 권한이 없다.
RUN useradd -m -d /work -s /bin/bash agent && mkdir -p /work && chown agent:agent /work
WORKDIR /work
CMD ["sleep", "infinity"]
