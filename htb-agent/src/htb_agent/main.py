"""
HTB 에이전트 CLI 진입점 (Kali 런타임)
======================================

사용 예:
  python3 -m htb_agent.main 10.129.1.5                  # 승인제 포트스캔
  python3 -m htb_agent.main 10.129.1.5 --auto           # 범위내 자동승인
  python3 -m htb_agent.main 10.129.1.5 --attacker-ip 10.10.14.5
  python3 -m htb_agent.main 10.129.1.5 --range 10.129.0.0/16

주의: 실제 실행은 Kali + HTB VPN 환경에서. 대상은 '권한이 확인된 HTB 머신'만.
"""

from __future__ import annotations

import argparse
import sys

from .scope_guard import ScopeGuard, ScopeViolation
from .environment import preflight, detect_vpn_ips
from .tools.runner import SubprocessRunner
from .tools.recon import ReconExecutor, auto_approve_in_scope
from .approval import interactive_approver
from .observation.compressor import render_observation, recommend_followup


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="htb-agent",
        description="HTB 머신 승인제 풀이 에이전트 (Kali). 권한 확인된 대상만.",
    )
    p.add_argument("target", help="대상 HTB 머신 IP (허용 대역 내)")
    p.add_argument("--range", action="append", dest="ranges",
                   help="허용 타겟 CIDR (반복 가능). 생략 시 HTB 기본 대역")
    p.add_argument("--attacker-ip", action="append", dest="attacker_ips",
                   help="공격자 VPN IP (반복 가능). 생략 시 tun0 자동탐지")
    p.add_argument("--auto", action="store_true",
                   help="범위내+검증통과 명령 자동승인 (비대화형)")
    p.add_argument("--max-attempts", type=int, default=4,
                   help="포트스캔 폴백 최대 시도 (기본 4, 무한루프 방지)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # 1) Scope Guard 구성 + 타겟 바인딩
    guard = ScopeGuard.from_cidr_strings(args.ranges)
    try:
        guard.bind_target(args.target)
    except ScopeViolation as e:
        print(f"⛔ {e}", file=sys.stderr)
        return 2

    # 2) 공격자 VPN IP 등록 (지정 or 자동탐지)
    attacker = args.attacker_ips or detect_vpn_ips()
    for ip in attacker:
        try:
            guard.add_attacker_ip(ip)
        except ValueError as e:
            print(f"⚠️ 공격자 IP 무시: {e}", file=sys.stderr)

    # 3) 환경 프리플라이트
    pf = preflight(required_tool_keys=["nmap"])
    print(pf.render())
    print(f"\n타겟 바인딩: {guard.bound_target} | 허용대역: {guard.describe()} | 공격자IP: {attacker or '(없음)'}\n")

    # 4) Recon 실행 (승인제)
    approver = auto_approve_in_scope if args.auto else interactive_approver
    executor = ReconExecutor(guard, SubprocessRunner(), approver,
                             max_attempts=args.max_attempts)
    report = executor.run_portscan()
    print("\n" + report.summary())

    # 5) 관측 요약 + 다음 '경우의 수' 제안
    if report.host is not None:
        print("\n" + render_observation(report.host))
    if report.status != "success":
        # 폴백 제안(실행은 안 함 — 사람이 판단)
        last = next((a.result for a in reversed(report.attempts) if a.result), None)
        if last is not None:
            sugg = recommend_followup(last)
            if sugg:
                print("\n[다음 경우의 수 제안]")
                for s in sugg:
                    print(f"  · {s}")
    return 0 if report.status == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
