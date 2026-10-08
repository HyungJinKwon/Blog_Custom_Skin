"""
포트스캔 폴백 — nmap 이 없을 때 순수 파이썬 TCP-connect 스캔
==============================================================

nmap 미설치 환경(일부 CI·최소 컨테이너·라이브 벤치마크)에서 정찰이 한 걸음도 못 나가던 문제를
메운다. **바인딩된 타겟에만**, TCP connect(페이로드 없음)로 열린 포트를 확인하고, 배너를 조금
읽어 nmap 과 같은 자료구조(NmapResult/NmapHost/Port)로 돌려준다. 범위 밖으로는 절대 나가지
않는다(스캔 대상은 호출부가 넘긴 타겟 하나뿐).

주의: nmap 의 서비스/버전 탐지를 대체하지 않는다 — 열린 포트 + 흔한 포트의 서비스 추정 +
짧은 배너까지만. nmap 이 있으면 항상 nmap 을 쓴다(이 폴백은 '없을 때만').
"""

from __future__ import annotations

import socket
from typing import Callable

from ..observation.parsers import NmapHost, NmapResult, Port

# 흔한 포트 → 서비스 추정(프로파일러·KB 라우팅용). nmap 서비스명과 맞춘다.
PORT_SERVICE: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    512: "exec", 513: "login", 514: "shell", 587: "submission", 636: "ldaps",
    873: "rsync", 993: "imaps", 995: "pop3s", 1433: "ms-sql-s", 1521: "oracle",
    2049: "nfs", 3000: "http", 3306: "mysql", 3389: "ms-wbt-server", 5000: "http",
    5432: "postgresql", 5601: "http", 5985: "wsman", 5986: "wsman", 6379: "redis",
    8000: "http", 8008: "http", 8080: "http-proxy", 8443: "https-alt", 8888: "http",
    9000: "http", 9200: "http", 11211: "memcached", 27017: "mongod",
}

# 폴백 기본 스캔 포트(흔한 상위 집합). 호출부가 '아는 포트'를 더 줄 수 있다.
DEFAULT_PORTS: tuple[int, ...] = tuple(sorted(PORT_SERVICE))

ConnectProbe = Callable[[str, int, float], "str | None"]
#   (host, port, timeout) -> 열려 있으면 배너(없으면 ""), 닫혀 있으면 None


def _probe(host: str, port: int, timeout: float) -> "str | None":
    """TCP connect 후 짧게 배너를 읽는다(페이로드 송신 없음). 닫혀 있으면 None."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(min(0.8, timeout))
            try:
                data = s.recv(128)
            except (OSError, socket.timeout):
                data = b""
            return data.decode("latin-1", "replace").strip()
    except (OSError, socket.timeout, ValueError):
        return None


def socket_scan(host: str, ports=DEFAULT_PORTS, timeout: float = 1.0,
                probe: ConnectProbe | None = None) -> NmapResult:
    """`host` 의 `ports` 를 TCP-connect 로 스캔해 NmapResult 로 반환.
    범위 보증은 호출부 책임(바인딩된 타겟만 넘길 것). probe 주입 시 실제 소켓 대신 사용(테스트)."""
    probe = probe or _probe
    open_ports: list[Port] = []
    seen: set[int] = set()
    for p in ports:
        p = int(p)
        if p in seen or not (0 < p < 65536):
            continue
        seen.add(p)
        banner = probe(host, p, timeout)
        if banner is None:
            continue
        svc = PORT_SERVICE.get(p, "unknown")
        # 배너 첫 줄만, 제품 힌트로(과신 금지 — 버전 정규화는 nmap 몫)
        product = ""
        first = (banner or "").splitlines()[0].strip() if banner else ""
        if first and len(first) <= 80 and first.isprintable():
            product = first
        open_ports.append(Port(port=p, proto="tcp", state="open",
                               service=svc, product=product))
    if not open_ports:
        # 연결이 하나도 안 되면 '다운처럼' — 호출부가 다음 방안을 고르게(여기선 폴백이 끝)
        return NmapResult(hosts=[NmapHost(address=host, state="unknown",
                                          reason="socket-scan: 열린 포트 없음")],
                          any_up=False, seems_down=True)
    host_obj = NmapHost(address=host, state="up", reason="socket-scan(connect)",
                        ports=open_ports)
    return NmapResult(hosts=[host_obj], any_up=True, seems_down=False)
