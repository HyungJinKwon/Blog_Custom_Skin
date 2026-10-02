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
from .tools.recon import auto_approve_in_scope
from .approval import interactive_approver
from .knowledge import KnowledgeBase
from .orchestrator import Orchestrator


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
    p.add_argument("--max-enum", type=int, default=6,
                   help="enum 자동실행 최대 개수 (기본 6, 무한확장 방지)")
    p.add_argument("--knowledge", default="knowledge",
                   help="지식베이스 디렉토리 (기본 ./knowledge). 사용자 규칙/노트로 성장")
    p.add_argument("--llm", choices=["none", "claude", "ollama"], default="none",
                   help="LLM 두뇌 백엔드 (기본 none=규칙기반). claude=Claude API, ollama=로컬")
    p.add_argument("--llm-tier", choices=["cheap", "standard", "strong"], default="standard",
                   help="LLM 티어 (비용/성능)")
    return p


def _build_llm_router(kind: str, tier_name: str):
    """LLM 백엔드 구성. 사용 불가면 (None, 사유) 반환."""
    if kind == "none":
        return None, "LLM 미사용(규칙기반)"
    from .llm.base import Tier
    from .llm.router import LLMRouter
    if kind == "claude":
        from .llm.claude_provider import ClaudeProvider
        provider = ClaudeProvider()
    else:
        from .llm.ollama_provider import OllamaProvider
        provider = OllamaProvider()
    ok, reason = provider.available()
    if not ok:
        return None, f"{kind} 사용 불가: {reason}"
    return LLMRouter(provider, default_tier=Tier(tier_name)), f"{kind}({tier_name})"


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

    # 4) 지식베이스 로드 (사용자 학습데이터로 성장)
    kb = KnowledgeBase.load(base_dir=args.knowledge)
    print(f"지식베이스: 규칙 {len(kb.rules)}개, 노트 {len(kb.notes)}개 로드\n")

    # 5) LLM 두뇌 구성(선택)
    llm_router, llm_status = _build_llm_router(args.llm, args.llm_tier)
    print(f"LLM: {llm_status}\n")

    # 6) 오케스트레이션 (유한 단계: RECON→PROFILE→ENUM→(LLM)→REPORT)
    approver = auto_approve_in_scope if args.auto else interactive_approver
    orchestrator = Orchestrator(guard, SubprocessRunner(), kb, approver,
                                max_enum=args.max_enum,
                                recon_max_attempts=args.max_attempts,
                                llm_router=llm_router)
    report = orchestrator.run()
    print("\n" + report.summary())
    return 0 if report.status == "done" else 1


if __name__ == "__main__":
    raise SystemExit(main())
