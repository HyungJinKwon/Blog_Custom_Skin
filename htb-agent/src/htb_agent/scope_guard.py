"""
Scope Guard — 교육용 경계 강제 모듈
====================================

이 에이전트는 **권한이 확인된 HTB(Hack The Box) 머신** 에 한정해서만 동작한다.
Scope Guard 는 모든 공격성 명령이 실행되기 직전 통과해야 하는 게이트로,
대상이 HTB VPN 할당 대역 안에 있는지 검증한다. 화이트리스트 밖의 IP 가
단 하나라도 명령에 섞여 있으면 실행을 거부하고 로깅한다.

설계 원칙:
  1. Fail-closed  : 판단이 모호하면 '거부'가 기본값이다.
  2. All-or-none  : 명령에 등장하는 '모든' IP 가 범위 안이어야 통과한다.
                    (두 번째 대상을 몰래 끼워 넣는 것을 차단)
  3. No-bypass    : 이 게이트를 우회하는 경로를 다른 모듈에 두지 않는다.

이 경계가 "교육용 도구" 와 "무차별 공격 도구" 를 가르는 결정적 분기점이다.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from typing import Iterable

logger = logging.getLogger("htb_agent.scope_guard")

# HTB 가 통상적으로 머신 대상에 할당하는 대역 (config 로 덮어쓸 수 있음).
#   - 10.10.10.0/23 : 전통적인 Labs 머신 대역 (10.10.10.x / 10.10.11.x)
#   - 10.129.0.0/16 : 최신 Release Arena / 머신 대역
DEFAULT_HTB_RANGES: tuple[str, ...] = (
    "10.10.10.0/23",
    "10.129.0.0/16",
)

# 명령 문자열에서 IPv4 를 추출하기 위한 패턴.
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class ScopeViolation(Exception):
    """대상이 허용된 HTB 범위를 벗어났을 때 발생."""


@dataclass
class ScopeGuard:
    """허용된 CIDR 대역에 대해 대상/명령을 검증한다."""

    allowed_cidrs: list[ipaddress.IPv4Network] = field(default_factory=list)

    @classmethod
    def from_cidr_strings(cls, cidrs: Iterable[str] | None = None) -> "ScopeGuard":
        """문자열 CIDR 목록으로 가드를 생성한다. None 이면 HTB 기본값 사용."""
        raw = list(cidrs) if cidrs else list(DEFAULT_HTB_RANGES)
        networks: list[ipaddress.IPv4Network] = []
        for c in raw:
            try:
                networks.append(ipaddress.ip_network(c, strict=False))
            except ValueError as exc:
                raise ValueError(f"잘못된 CIDR 설정: {c!r} ({exc})") from exc
        if not networks:
            raise ValueError("Scope Guard: 허용 대역이 비어 있습니다. fail-closed.")
        logger.info("Scope Guard 활성화 — 허용 대역: %s", [str(n) for n in networks])
        return cls(allowed_cidrs=networks)

    # ── 단일 IP 검증 ────────────────────────────────────────────────
    def is_in_scope(self, ip: str) -> bool:
        """주어진 IP 가 허용 대역 안에 있으면 True."""
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError:
            return False  # 파싱 불가 → fail-closed
        return any(addr in net for net in self.allowed_cidrs)

    def assert_in_scope(self, ip: str) -> None:
        """범위를 벗어나면 ScopeViolation 을 발생시킨다."""
        if not self.is_in_scope(ip):
            logger.warning("범위 위반 차단 — 대상 IP=%s 는 허용 대역 밖입니다.", ip)
            raise ScopeViolation(
                f"대상 {ip} 은(는) 허용된 HTB 대역 밖입니다. 실행을 거부합니다."
            )

    # ── 명령 전체 검증 (All-or-none) ────────────────────────────────
    def assert_command_in_scope(self, command: str) -> None:
        """
        명령 문자열에 등장하는 '모든' IPv4 가 허용 대역 안인지 검증한다.
        - IP 가 하나도 없으면: 대상이 불명확하므로 거부 (fail-closed).
        - IP 가 하나라도 범위 밖이면: 거부.
        """
        found = _IPV4_RE.findall(command)
        if not found:
            logger.warning("명령에 대상 IP 가 없어 거부: %s", command)
            raise ScopeViolation(
                "명령에서 대상 IP 를 찾지 못했습니다. 안전을 위해 거부합니다."
            )
        out_of_scope = [ip for ip in found if not self.is_in_scope(ip)]
        if out_of_scope:
            logger.warning("범위 밖 IP 포함 명령 차단: %s (문제 IP=%s)",
                           command, out_of_scope)
            raise ScopeViolation(
                f"명령에 허용 대역 밖 IP 가 포함됐습니다: {out_of_scope}. 거부합니다."
            )

    def describe(self) -> str:
        """현재 허용 대역을 사람이 읽기 좋은 문자열로 반환."""
        return ", ".join(str(n) for n in self.allowed_cidrs)
