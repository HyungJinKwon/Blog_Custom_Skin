"""
Command Fixer (Results Verifier) — 실행 전 '명령 자동 교정'
============================================================

AutoPentester(2510.05605)의 Results Verifier 아이디어: LLM 이 자주 내는 '거의 맞지만 틀린'
명령(예: RHOST 를 엉뚱한 IP 로, 타겟 자리에 자리표시자 `<target>`) 때문에 범위 밖으로 거부되어
한 번의 시도를 통째로 버리는 일을 줄인다. 그 논문에서 불완전 명령을 80% 줄인 핵심 모듈.

안전 원칙(이 구현의 경계):
  · **복구만** — 원래 명령이 범위 안이면 절대 건드리지 않는다(호출부가 그렇게 쓴다).
  · 타겟 자리의 **자리표시자**(<target> 등)를 바인딩된 타겟으로 치환.
  · 명령에 바인딩 타겟도 공격자 IP 도 아닌 **사설/타겟대역 IPv4 가 '정확히 하나'** 있을 때만,
    그것을 바인딩된 타겟으로 교정(공격자 IP·루프백은 손대지 않음 — 리버스쉘 LHOST 보호).
  · 교정 후에도 반드시 검증→범위→승인 3관문을 다시 통과해야 실행된다(교정은 제안일 뿐).
"""

from __future__ import annotations

import ipaddress
import re

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# 타겟 자리에 흔히 남는 자리표시자(크리덴셜 {user}/{pass} 는 creds 가 따로 처리 — 여기선 타겟만)
_TARGET_PLACEHOLDERS = [
    "<target>", "<TARGET>", "<target-ip>", "<target_ip>", "<targetip>",
    "<ip>", "<IP>", "<rhost>", "<RHOST>", "<host>", "<HOST>",
    "TARGET_IP", "TARGETIP", "RHOST_IP", "target-ip", "<victim>", "<VICTIM>",
]


# 교정 대상이 될 수 있는 '랩/타겟 오타' 후보 대역 — 실제 RFC1918 사설망만.
# (파이썬 신버전의 ip.is_private 는 문서용 TEST-NET·CGNAT 등도 포함하므로 쓰지 않는다 —
#  공인/문서 IP 를 타겟으로 바꿔버리는 오작동 방지)
_RFC1918 = [ipaddress.ip_network(c) for c in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _is_private_or_target(ip: ipaddress.IPv4Address, allowed_nets) -> bool:
    if any(ip in net for net in allowed_nets):
        return True
    return any(ip in net for net in _RFC1918)


def correct_target(cmd: str, guard) -> tuple[str, str]:
    """명령의 타겟을 바인딩된 타겟으로 교정. 반환 (교정된 명령, 사유). 바꿀 게 없으면 (원본, "").
    guard: ScopeGuard — bound_target / attacker_ips / allowed_target_cidrs 를 참조."""
    target = getattr(guard, "bound_target", None)
    if target is None:
        return cmd, ""
    target_s = str(target)
    reasons: list[str] = []

    # 1) 타겟 자리표시자 치환
    new = cmd
    for ph in _TARGET_PLACEHOLDERS:
        if ph in new:
            new = new.replace(ph, target_s)
    if new != cmd:
        reasons.append("자리표시자→타겟")

    # 2) 잘못된 타겟 IP 교정 — 바인딩 타겟도 공격자 IP 도 아닌 사설/타겟대역 IPv4 가 '하나뿐'일 때만
    attacker = {str(a) for a in getattr(guard, "attacker_ips", set()) or set()}
    allowed_nets = list(getattr(guard, "allowed_target_cidrs", []) or [])
    wrong: list[str] = []
    for m in _IPV4.findall(new):
        if m == target_s or m in attacker:
            continue
        try:
            ip = ipaddress.ip_address(m)
        except ValueError:
            continue
        if isinstance(ip, ipaddress.IPv4Address) and _is_private_or_target(ip, allowed_nets):
            if m not in wrong:
                wrong.append(m)
    if len(wrong) == 1:
        new = re.sub(r"\b" + re.escape(wrong[0]) + r"\b", target_s, new)
        reasons.append(f"IP {wrong[0]}→타겟")

    if new == cmd:
        return cmd, ""
    return new, " · ".join(reasons)
