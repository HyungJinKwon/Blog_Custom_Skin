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
from . import __version__
from .knowledge import KnowledgeBase
from .orchestrator import Orchestrator
from .profiles import JEOPARDY_CATEGORIES


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="assassin",
        description="ASSASSIN — HTB 머신 승인제 풀이 에이전트 (Kali). 권한 확인된 대상만.",
    )
    p.add_argument("--version", action="version", version=f"ASSASSIN {__version__}")
    p.add_argument("--doctor", action="store_true",
                   help="환경 자가진단(도구·LLM·VPN 점검, 스캔 안 함). 완전 초보자 권장 첫 실행")
    p.add_argument("--revshell", metavar="LHOST:LPORT", default=None,
                   help="리버스쉘 페이로드 생성(실행 안 함). 'IP:PORT' 또는 'PORT'"
                        "(공격자 IP 자동/--attacker-ip). 권한 확인 대상 전용")
    p.add_argument("--learn", metavar="TOPIC", default=None,
                   help="권위 출처 자가학습(도구·공격기법·개념·프로토콜)을 지식베이스에 저장. "
                        "예: --learn kerberoasting / burp / http. 목록: --learn list")
    p.add_argument("--cloud", metavar="NAME", default=None,
                   help="AWS/S3 열거 자동 준비(생성 안 실행). 호스트명/도메인에서 버킷명 "
                        "후보+비인증 점검 생성. 예: --cloud acme.htb. 권한 확인 자산 전용")
    p.add_argument("--privesc", metavar="OS", default=None,
                   choices=["linux", "windows", "windows_ad"],
                   help="권한상승 플레이북 자동 준비(생성 안 실행). OS 별 열거·점검·LPE "
                        "체크리스트 생성. 예: --privesc linux. 획득한 대상 셸에서 직접 실행")
    p.add_argument("--crack", metavar="HASH", default=None,
                   help="해시 크래킹 자동 준비(생성 안 실행). 해시 종류 식별 + john/hashcat "
                        "명령 생성. 예: --crack '$krb5tgs$23$...'. 권한 확인 자산 해시 전용")
    p.add_argument("target", nargs="?", default=None,
                   help="대상(IP 또는 호스트명/URL). HTB=허용대역 내 IP, "
                   "CTF/Dreamhack=챌린지 host:port/URL")
    p.add_argument("--platform", choices=["htb", "dreamhack", "ctf"], default=None,
                   help="플랫폼 프로파일 (기본 htb). dreamhack/ctf=단일 타겟+flag{} 모드")
    p.add_argument("--category", choices=[k for k, _ in JEOPARDY_CATEGORIES], default=None,
                   help="Jeopardy 카테고리 힌트(web/pwn/rev/crypto/forensic/misc). "
                        "CTF/Dreamhack 에서 LLM 제안을 카테고리에 맞게 유도")
    p.add_argument("--flag-prefix", action="append", dest="flag_prefixes",
                   help="우선 인식할 플래그 접두 (반복 가능, 예: --flag-prefix DH). "
                        "플랫폼 기본값에 추가")
    p.add_argument("--range", action="append", dest="ranges",
                   help="허용 타겟 CIDR (반복 가능). 생략 시 플랫폼 기본(HTB만 대역 강제)")
    p.add_argument("--attacker-ip", action="append", dest="attacker_ips",
                   help="공격자 VPN IP (반복 가능). 생략 시 tun0 자동탐지")
    p.add_argument("--lport", type=int, default=4444,
                   help="리버스쉘 리스너 포트(자동 준비 페이로드용, 기본 4444)")
    p.add_argument("--cred", action="append", dest="creds",
                   help="자격증명 'user:pass' / 'user:pass:domain' / "
                        "'user:pass:domain:nthash' (반복 가능). Pass-the-Hash 는 "
                        "'user:<32hex>' 또는 'user::domain:<NT|LM:NT>'. "
                        "{user}/{pass}/{domain}/{hash} 제안을 실행 후보로 승격")
    p.add_argument("--config", help="설정 파일(.json/.yaml). 우선순위: CLI > 설정파일 > 기본값")
    p.add_argument("--auto", action="store_true",
                   help="완전 자동: 범위내+검증통과만 실행, 범위 밖은 조용히 건너뜀(무프롬프트)")
    p.add_argument("--manual", action="store_true",
                   help="완전 수동: 모든 명령을 실행 전 확인(승인제 최대)")
    p.add_argument("--no-enrich", action="store_true",
                   help="CVE/CWE 자동 수집(NVD/GitHub) 비활성")
    p.add_argument("--offline", action="store_true",
                   help="오프라인: 네트워크 수집 금지(캐시만 사용)")
    p.add_argument("--enrich-cache", default=None,
                   help="CVE 캐시 디렉토리 (기본 <knowledge>/cve_cache)")
    # 아래 덮어쓰기 가능 옵션은 기본값 None → 설정파일/내장기본값과 병합
    p.add_argument("--max-attempts", type=int, default=None,
                   help="포트스캔 폴백 최대 시도 (기본 4, 무한루프 방지)")
    p.add_argument("--max-enum", type=int, default=None,
                   help="enum 자동실행 최대 개수 (기본 6, 무한확장 방지)")
    p.add_argument("--max-rounds", type=int, default=None,
                   help="ENUM/LLM 반복 라운드 수 (기본 2, 무한루프 방지)")
    p.add_argument("--max-sweeps", type=int, default=None,
                   help="단계 재진입 스윕 수 (기본 2). 새 관측·크리덴셜로 이전 단계 "
                        "재시도. 상태 정체 시 조기종료(유한)")
    p.add_argument("--variants", type=int, default=None,
                   help="명령당 옵션 조합 변형 수 (기본 2, 1=변형끔). 경우의 수 시도")
    p.add_argument("--knowledge", default=None,
                   help="지식베이스 디렉토리 (기본 ./knowledge). 사용자 규칙/노트로 성장")
    p.add_argument("--llm", choices=["none", "claude", "ollama", "hybrid"], default=None,
                   help="LLM 두뇌 백엔드 (기본 none=규칙기반). claude=API, ollama=로컬, "
                        "hybrid=둘을 단계 난이도로 라우팅+폴백(장점극대·단점보완)")
    p.add_argument("--llm-tier", choices=["cheap", "standard", "strong"], default=None,
                   help="LLM 티어 (비용/성능)")
    p.add_argument("--state-dir", default=None,
                   help="세션 상태 저장 디렉토리 (기본 ./state)")
    p.add_argument("--resume", action="store_true",
                   help="저장된 상태에서 재개 (RECON 재사용, 재스캔 생략)")
    p.add_argument("--no-save", action="store_true", help="상태 저장 안 함")
    p.add_argument("--log-file", default=None,
                   help="감사 로그(JSONL) 경로. 생략 시 <state-dir>/audit_<타겟>.jsonl")
    p.add_argument("--no-audit", action="store_true", help="감사 로그 비활성")
    p.add_argument("--writeup", nargs="?", const="__auto__", default=None,
                   help="풀이 라이트업 Markdown 생성(경로 생략 시 writeup_<타겟>.md)")
    p.add_argument("--writeup-format", choices=["htb", "tistory"], default="htb",
                   help="라이트업 형식: htb(기본, htb-ctf-writeup-v5) / tistory(13섹션)")
    p.add_argument("--json", nargs="?", const="__auto__", default=None, dest="json_out",
                   help="결과를 기계판독 JSON 으로 내보내기(경로 생략 시 <state-dir>/report_<타겟>.json)")
    p.add_argument("--html", nargs="?", const="__auto__", default=None, dest="html_out",
                   help="결과를 HTML 대시보드로 내보내기(블루/네이비, 경로 생략 시 <state-dir>/report_<타겟>.html)")
    return p


def _build_llm_router(kind: str, tier_name: str):
    """LLM 백엔드 구성. 사용 불가면 (None, 사유) 반환."""
    if kind == "none":
        return None, "LLM 미사용(규칙기반)"
    from .llm.base import Tier
    from .llm.router import LLMRouter, HybridRouter
    from .llm.claude_provider import ClaudeProvider
    from .llm.ollama_provider import OllamaProvider

    def _mk(provider):
        ok, reason = provider.available()
        return (LLMRouter(provider, default_tier=Tier(tier_name)) if ok else None), reason

    if kind == "hybrid":
        # 두 백엔드를 단계 난이도로 라우팅 + 상호 폴백(장점극대·단점보완)
        local, lreason = _mk(OllamaProvider())     # 열거·일반 → 무료·토큰절약
        strong, sreason = _mk(ClaudeProvider())    # 권한상승·exploit → 정확
        if local is None and strong is None:
            return None, f"hybrid 사용 불가: ollama({lreason}) / claude({sreason})"
        status = (f"hybrid(local=ollama[{'OK' if local else 'X'}], "
                  f"strong=claude[{'OK' if strong else 'X'}], 티어={tier_name})")
        return HybridRouter(local=local, strong=strong,
                            default_tier=Tier(tier_name)), status

    provider = ClaudeProvider() if kind == "claude" else OllamaProvider()
    router, reason = _mk(provider)
    if router is None:
        return None, f"{kind} 사용 불가: {reason}"
    return router, f"{kind}({tier_name})"


def main(argv: list[str] | None = None, runner=None) -> int:
    # runner 주입 가능(테스트). 기본은 실제 Kali 용 SubprocessRunner.
    parser = build_parser()
    args = parser.parse_args(argv)
    from . import ui
    from .profiles import get_profile

    # 환경 자가진단(스캔 안 함) — 완전 초보자 권장 첫 실행
    if args.doctor:
        from .doctor import run_doctor
        text, ok = run_doctor()
        print(text)
        return 0 if ok else 2

    # 리버스쉘 페이로드 생성(스캔·실행 안 함)
    if args.revshell:
        from . import revshell
        default_host = (args.attacker_ips[0] if args.attacker_ips
                        else (detect_vpn_ips() or [None])[0])
        try:
            lhost, lport = revshell.parse_target(args.revshell, default_host)
        except ValueError as e:
            print(ui.mark_err(str(e)), file=sys.stderr)
            return 2
        print(revshell.render(lhost, lport))
        return 0

    # AWS/S3 열거 자동 준비(스캔·실행 안 함) — 버킷 후보+점검 생성
    if args.cloud:
        from . import cloud
        print(cloud.render([args.cloud]))
        return 0

    # 권한상승 플레이북 자동 준비(스캔·실행 안 함) — OS별 체크리스트 생성
    if args.privesc:
        from . import privesc
        default_atk = (args.attacker_ips[0] if args.attacker_ips
                       else (detect_vpn_ips() or [""])[0])
        print(privesc.render(args.privesc, default_atk or ""))
        return 0

    # 해시 크래킹 자동 준비(실행 안 함) — 종류 식별 + john/hashcat 명령 생성
    if args.crack:
        from . import crack
        print(crack.render(args.crack))
        return 0

    # 권위 출처 자가학습(스캔 안 함) — 지식베이스에 노트 저장(P1 유지)
    if args.learn:
        from . import learn
        if args.learn.strip().lower() in ("list", "topics", "?"):
            print(ui.heading("학습 가능 주제(권위 출처)", "📚"))
            print("  " + ", ".join(learn.topics()))
            return 0
        import os as _oslearn
        kdir = args.knowledge or "knowledge"
        learner = learn.ReferenceLearner(
            cache_dir=_oslearn.path.join(kdir, "notes", "learned"),
            enabled=not args.offline)
        res = learner.learn(args.learn)
        print(res.summary())
        return 0 if res.refs else 2

    if not args.target:
        parser.error("target 이 필요합니다 (또는 --doctor / --revshell / --cloud / --privesc / --crack / --learn). 예: assassin 10.129.1.5")

    # 0) 설정 파일 로드 + 우선순위 해소 (CLI > config > 기본값)
    from .config import load_config, pick, Config, ConfigError
    try:
        cfg = load_config(args.config) if args.config else Config()
    except ConfigError as e:
        print(ui.mark_err(f"설정 오류: {e}"), file=sys.stderr)
        return 2
    # 플랫폼 프로파일(HTB/Dreamhack/CTF)
    try:
        profile = get_profile(pick(args.platform, cfg.platform, "htb"))
    except ValueError as e:
        print(ui.mark_err(str(e)), file=sys.stderr)
        return 2
    print(ui.banner(profile.banner_subtitle))
    flag_prefixes = tuple(profile.flag_prefixes) + tuple(args.flag_prefixes or ())
    ranges = pick(args.ranges, cfg.allowed_ranges,
                  list(profile.default_ranges) or None)
    max_attempts = pick(args.max_attempts, cfg.max_attempts, 4)
    max_enum = pick(args.max_enum, cfg.max_enum, 6)
    max_rounds = pick(args.max_rounds, cfg.max_rounds, 2)
    max_sweeps = pick(args.max_sweeps, cfg.max_sweeps, 2)
    max_variants = pick(args.variants, cfg.max_variants, 2)
    knowledge_dir = pick(args.knowledge, cfg.knowledge_dir, "knowledge")
    llm_kind = pick(args.llm, cfg.llm_backend, "none")
    llm_tier = pick(args.llm_tier, cfg.llm_tier, "standard")
    state_dir = pick(args.state_dir, cfg.state_dir, "state")

    # 1) Scope Guard 구성 + 타겟 바인딩 (플랫폼별 대역강제/호스트명 허용)
    guard = ScopeGuard.from_cidr_strings(
        ranges, enforce_ranges=profile.enforce_ranges,
        allow_hostname_target=profile.allow_hostname_target)
    try:
        guard.bind_target(args.target)
    except ScopeViolation as e:
        print(ui.mark_err(str(e)), file=sys.stderr)
        return 2

    # 2) 공격자 VPN IP 등록 (지정 or 설정 or 자동탐지)
    attacker = pick(args.attacker_ips, cfg.attacker_ips, None) or detect_vpn_ips()
    for ip in attacker:
        try:
            guard.add_attacker_ip(ip)
        except ValueError as e:
            print(ui.mark_warn(f"공격자 IP 무시: {e}"), file=sys.stderr)

    # 3) 환경 프리플라이트
    pf = preflight(required_tool_keys=["nmap"])
    print(pf.render())
    _mode = "완전자동" if args.auto else ("완전수동" if args.manual else "스마트(범위밖만 확인)")
    _plat = ui.accent2(profile.name) + ui.dim(f"  ({profile.flag_kind}")
    _plat += ui.dim(f" · {args.category})") if (profile.is_jeopardy and args.category) \
        else ui.dim(")")
    print(ui.panel("세션", [
        ui.kv("플랫폼", _plat, 8),
        ui.kv("타겟", ui.accent2(str(guard.bound_target or guard.bound_host)), 8),
        ui.kv("범위", guard.describe(), 8),
        ui.kv("공격자IP", (ui.ok(", ".join(attacker)) if attacker
                        else ui.dim("(없음)")), 8),
        ui.kv("승인", ui.info(_mode), 8),
        ui.kv("플래그", ui.dim("접두 " + (", ".join(flag_prefixes) or "자동") + " · TAG{} 자동인식"), 8),
    ], style="navy") + "\n")

    # 4) 지식베이스 + 취약점 KB 로드 (사용자 학습데이터로 성장)
    kb = KnowledgeBase.load(base_dir=knowledge_dir)
    from .vuln import VulnKB
    vuln_kb = VulnKB.load(base_dir=knowledge_dir)
    print(ui.kv("지식베이스", f"규칙 {ui.bold(str(len(kb.rules)))}개 · 노트 "
                f"{ui.bold(str(len(kb.notes)))}개 · 취약점규칙 "
                f"{ui.bold(str(len(vuln_kb.rules)))}개", 10))

    # 5) LLM 두뇌 구성(선택)
    llm_router, llm_status = _build_llm_router(llm_kind, llm_tier)
    print(ui.kv("LLM", ui.info(llm_status), 10) + "\n")

    # 6) 상태 저장소 (중단/재개) + 자격증명 볼트
    from .state import StateStore
    from .creds import CredentialVault, Credential
    store = None if args.no_save else StateStore(state_dir)
    vault = CredentialVault.from_cli(args.creds)
    # 실행 결과 기반 변형 학습(세션 넘어 누적) — <state-dir>/variant_stats.json
    from .variant_stats import VariantStats
    import os as _osvs
    vstats_path = _osvs.path.join(state_dir, "variant_stats.json")
    variant_stats = VariantStats() if args.no_save else VariantStats.load(vstats_path)
    if args.resume and store and store.exists(args.target):
        prior = store.load(args.target)
        if prior:
            print("재개할 저장 상태 발견:\n" + prior.summary() + "\n")
            for d in prior.credentials:   # 저장된 자격증명 재사용
                vault.add(Credential.from_dict(d))
    if vault.creds:
        print(f"자격증명 볼트: {[c.label() for c in vault.creds]}\n")

    # 6.5) 감사 로그
    from .audit import AuditLog, NullAudit
    import os as _os
    if args.no_audit:
        audit = NullAudit()
    else:
        log_path = args.log_file or _os.path.join(
            state_dir, f"audit_{StateStore._safe(args.target)}.jsonl")
        audit = AuditLog(log_path)
        print(f"감사 로그: {log_path}\n")

    # 6.6) CVE/CWE 자동 수집기(공식 출처, 기본 활성 · 캐시 · 오프라인 안전)
    from .enrich import Enricher
    enrich_cache = args.enrich_cache or _os.path.join(knowledge_dir, "cve_cache")
    enricher = None if args.no_enrich else Enricher(
        cache_dir=enrich_cache, enabled=not args.offline)
    print(ui.kv("CVE수집", (ui.dim("비활성") if args.no_enrich
                else (ui.info("캐시만(오프라인)") if args.offline
                      else ui.ok("자동(NVD/GitHub) · 캐시 " + enrich_cache))), 10) + "\n")

    # 7) 오케스트레이션 (유한 단계: RECON→PROFILE→ENUM→(LLM)→REPORT)
    # 승인 모드: --auto(완전자동) / --manual(완전수동) / 기본=스마트(범위밖만 확인)
    from .approval import smart_approver
    if args.auto:
        approver = auto_approve_in_scope
    elif args.manual:
        approver = interactive_approver
    else:
        approver = smart_approver
    orchestrator = Orchestrator(guard, runner or SubprocessRunner(), kb, approver,
                                max_enum=max_enum,
                                recon_max_attempts=max_attempts,
                                max_rounds=max_rounds,
                                max_sweeps=max_sweeps,
                                max_variants=max_variants,
                                llm_router=llm_router, vuln_kb=vuln_kb,
                                vault=vault,   # 항상 전달(수확 자격 수용 — 빈 볼트도 안전)
                                flag_kind=profile.flag_kind,
                                flag_prefixes=flag_prefixes,
                                enricher=enricher,
                                platform_name=profile.name,
                                category=(args.category or ""),
                                revshell_port=args.lport,
                                variant_stats=variant_stats,
                                state_store=store, resume=args.resume, audit=audit)
    report = orchestrator.run()
    if not args.no_save:
        variant_stats.save(vstats_path)   # 학습 결과 영속화(다음 실행에 반영)
    print("\n" + report.summary())
    if llm_router is not None and llm_router.calls:
        print("\n" + llm_router.cost_summary())

    # 8) 라이트업 생성(선택)
    if args.writeup is not None:
        from .writeup import generate_writeup, generate_tistory
        from .state import StateStore
        gen = generate_tistory if args.writeup_format == "tistory" else generate_writeup
        md = gen(report, attacker_ip=(attacker[0] if attacker else None))
        path = (args.writeup if args.writeup != "__auto__"
                else f"writeup_{StateStore._safe(args.target)}.md")
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(md)
            print(f"\n라이트업 생성: {path}")
        except OSError as e:
            print(f"\n⚠️ 라이트업 저장 실패: {e}", file=sys.stderr)

    # 9) 구조화 결과 내보내기(선택) — JSON(기계판독) / HTML(대시보드)
    if args.json_out is not None or args.html_out is not None:
        from . import report_export
        from .state import StateStore
        safe = StateStore._safe(args.target)
        _os.makedirs(state_dir, exist_ok=True)
        if args.json_out is not None:
            jp = (args.json_out if args.json_out != "__auto__"
                  else _os.path.join(state_dir, f"report_{safe}.json"))
            try:
                with open(jp, "w", encoding="utf-8") as f:
                    f.write(report_export.to_json(report))
                print(f"JSON 결과 내보내기: {jp}")
            except OSError as e:
                print(f"⚠️ JSON 내보내기 실패: {e}", file=sys.stderr)
        if args.html_out is not None:
            hp = (args.html_out if args.html_out != "__auto__"
                  else _os.path.join(state_dir, f"report_{safe}.html"))
            try:
                with open(hp, "w", encoding="utf-8") as f:
                    f.write(report_export.to_html(report))
                print(f"HTML 대시보드 내보내기: {hp}")
            except OSError as e:
                print(f"⚠️ HTML 내보내기 실패: {e}", file=sys.stderr)

    return 0 if report.status == "done" else 1


if __name__ == "__main__":
    raise SystemExit(main())
