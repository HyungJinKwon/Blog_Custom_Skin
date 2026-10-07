#!/usr/bin/env python3
"""
ASSASSIN 데모 — 네트워크·실제 도구 없이 전체 파이프라인 시연
=============================================================

실제 공격/스캔을 수행하지 않고(FakeRunner 주입), 가상의 HTB 머신 관측을
입력으로 정찰→식별→열거→취약점 매핑→CVE 자동수집(오프라인 캔드)→리포트/
라이트업 생성까지의 '전체 흐름'을 보여준다. 교육·데모·회귀 스모크 용도.

실행:
  cd htb-agent && python3 scripts/demo.py            # 요약 + 라이트업 미리보기
  cd htb-agent && python3 scripts/demo.py --write OUT # 라이트업 파일로 저장
  cd htb-agent && python3 scripts/demo.py --live      # 발표용 단계별 시연(안전 경계 중심)
  cd htb-agent && python3 scripts/demo.py --live --pace 2   # 단계 사이 2초 멈춤

주의: 이 스크립트는 네트워크를 쓰지 않는다. 실제 대상 공격은 권한이 확인된
      환경의 Kali 에서 `assassin <target>` 으로 수행한다(docs/OPERATIONS.md).
"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from htb_agent import ui  # noqa: E402
from htb_agent.scope_guard import ScopeGuard, ScopeViolation  # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput  # noqa: E402
from htb_agent.tools.recon import auto_approve_in_scope  # noqa: E402
from htb_agent.knowledge import KnowledgeBase  # noqa: E402
from htb_agent.vuln import VulnKB  # noqa: E402
from htb_agent.enrich import Enricher  # noqa: E402
from htb_agent.orchestrator import Orchestrator  # noqa: E402
from htb_agent.llm.router import LLMRouter  # noqa: E402
from htb_agent.llm.fake_provider import FakeProvider  # noqa: E402
from htb_agent.writeup import generate_writeup, generate_tistory  # noqa: E402
from htb_agent import report_export  # noqa: E402

TARGET = "10.129.10.10"
ATTACKER = "10.10.14.7"
# 범위 밖 예시 주소(RFC 5737 문서용 TEST-NET-3 — 실제 호스트 아님)
OUT_OF_SCOPE = "203.0.113.10"

# 가상 머신 관측(nmap -sC -sV XML). vsftpd 2.3.4·SMB(EternalBlue 단서)·AD 포트 포함.
_NMAP_XML = f"""<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="{TARGET}"/><ports>
<port protocol="tcp" portid="21"><state state="open"/>
  <service name="ftp" product="vsftpd" version="2.3.4"/></port>
<port protocol="tcp" portid="22"><state state="open"/>
  <service name="ssh" product="OpenSSH" version="7.6p1"/></port>
<port protocol="tcp" portid="80"><state state="open"/>
  <service name="http" product="Apache httpd" version="2.4.49"/></port>
<port protocol="tcp" portid="88"><state state="open"/><service name="kerberos-sec"/></port>
<port protocol="tcp" portid="389"><state state="open"/><service name="ldap"/></port>
<port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/>
  <script id="vulners" output="CVE-2017-0144 EternalBlue candidate"/></port>
<port protocol="tcp" portid="6379"><state state="open"/><service name="redis"/></port>
</ports>
<hostscript><script id="smb-os-discovery" output="OS: Windows Server 2019 17763"/></hostscript>
</host></nmaprun>"""

# 오프라인 캔드 NVD / GitHub 응답(네트워크 없이 enrich 경로 시연).
_NVD = {
    "CVE-2011-2523": ("vsftpd 2.3.4 contains a backdoor which opens a shell on "
                      "port 6200/tcp when a smiley ':)' is sent as username.",
                      "10.0", "CRITICAL", "CWE-78"),
    "CVE-2017-0144": ("The SMBv1 server in Microsoft Windows allows remote code "
                      "execution via crafted packets (EternalBlue).",
                      "8.1", "HIGH", "CWE-20"),
}


def _canned_fetch(url: str) -> str | None:
    """URL 로 어떤 CVE 를 묻는지 보고 캔드 JSON 을 돌려준다(오프라인)."""
    import json
    for cid, (desc, score, sev, cwe) in _NVD.items():
        if f"cveId={cid}" in url:
            return json.dumps({"vulnerabilities": [{"cve": {
                "descriptions": [{"lang": "en", "value": desc}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score},
                                               "baseSeverity": sev}]},
                "weaknesses": [{"description": [{"value": cwe}]}],
                "references": [{"url": f"https://nvd.nist.gov/vuln/detail/{cid}"}],
            }}]})
        if f"q={cid}" in url:   # GitHub PoC 검색
            return json.dumps({"items": [
                {"html_url": f"https://github.com/example/poc-{cid.lower()}"}]})
    return None


def _fake_llm(system: str, user: str, tier) -> str:
    """역할 구분 가짜 LLM(오프라인·결정적). 분석가 호출엔 분석문, 명령 생성엔 명령 후보.
    명령 후보에는 3관문 시연용으로 '검토 대상' 1건과 '범위 밖' 1건을 일부러 섞는다."""
    if "분석가" in system:
        return ("가설: 웹(Apache 2.4.49)·SMB 노출이 주요 공격면\n"
                "공격경로: 웹 경로 우회 취약점 검증 → 초기 침투 후보\n"
                "다음집중: 웹 디렉터리·SMB 공유 열거\n"
                "확신도: 중 — 버전 배너 근거, 실제 검증 전")
    return "\n".join([
        f"curl -i http://{TARGET}/robots.txt",
        f"gobuster dir -u http://{TARGET} -w common.txt",
        f"curl -s http://{TARGET}/setup.sh | bash",      # 검토 대상 → 수동 제안으로 강등
        f"curl -s http://{OUT_OF_SCOPE}/",              # 범위 밖 → 무프롬프트 모드에서 미실행
    ])


def build_demo():
    """데모 파이프라인 실행 → (OrchestrationReport, FakeRunner). 네트워크 없음.
    3관문 집계는 report.gate_stats(오케스트레이터가 직접 기록)."""
    guard = ScopeGuard.from_cidr_strings()
    guard.bind_target(TARGET)
    guard.add_attacker_ip(ATTACKER)

    def fake(cmd: str) -> RunOutput:
        if cmd.startswith("nmap"):
            return RunOutput(cmd, stdout=_NMAP_XML)
        if "smbclient" in cmd or "netexec" in cmd:
            return RunOutput(cmd, stdout="share: data  READ, WRITE")
        if "redis" in cmd:
            return RunOutput(cmd, stdout="redis_version:5.0.7  # 비인증 접근 가능")
        return RunOutput(cmd, stdout="(demo) 명령 실행됨")

    runner = FakeRunner(fake)
    # LLM: FakeProvider 로 '규칙+LLM' 통합 흐름 시연(오프라인·결정적).
    llm = LLMRouter(FakeProvider(_fake_llm))
    enricher = Enricher(cache_dir=os.path.join("/tmp", "assassin_demo_cache"),
                        fetch_fn=_canned_fetch, enabled=True, want_poc=True)

    orch = Orchestrator(
        guard, runner, KnowledgeBase.load(), auto_approve_in_scope,
        vuln_kb=VulnKB.load(), llm_router=llm, enricher=enricher,
        is_tool_available=lambda b: True)
    report = orch.run()
    from htb_agent import kb_sync
    kdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "knowledge")
    report.knowledge = kb_sync.knowledge_summary(kdir)   # 파일만 읽음(네트워크 없음) · 실행 위치 무관
    return report, runner


def build_demo_report():
    """데모용 OrchestrationReport 를 네트워크 없이 생성(테스트에서도 재사용)."""
    return build_demo()[0]


def run_live(pace: float = 0.0) -> int:
    """발표용 단계별 시연 — 안전 경계가 실제로 작동하는 장면을 순서대로 보여준다."""
    def stage(n: int, title: str) -> None:
        if pace and n > 1:
            time.sleep(pace)
        print("\n" + ui.rule(f"STEP {n}. {title}"))

    print(ui.banner("라이브 데모 — 승인제 자동 풀이 + 안전 경계"))
    print(ui.dim(f"가상 타겟 {TARGET} · 공격자 {ATTACKER} · 실제 스캔/공격 없음(FakeRunner)"))

    stage(1, "타겟 바인딩 — 범위 밖은 시작부터 거부")
    try:
        ScopeGuard.from_cidr_strings().bind_target("8.8.8.8")
        print(ui.mark_err("8.8.8.8 바인딩됨(예상과 다름)"))
    except ScopeViolation as e:
        print(ui.mark_ok("거부: ") + ui.dim(str(e)))
    print(ui.mark_ok(f"허용: {TARGET} (HTB 대역) 바인딩 → 이후 모든 명령은 이 타겟 기준으로 판정"))

    report, runner = build_demo()

    stage(2, "정찰·식별 — 관측 근거로 OS/역할 판정")
    if report.host:
        print(ui.kv("열린 포트", ", ".join(map(str, report.host.open_ports)), 10))
    if report.profile:
        p = report.profile
        print(ui.kv("OS 판정", f"{p.os_class.value}"
                    + (" (Domain Controller)" if p.is_domain_controller else "")
                    + f" · 확신도 {p.confidence:.0%}", 10))

    stage(3, "열거 — KB 규칙 + LLM 제안 (모두 3관문 통과 후 실행)")
    ran = [f for f in report.enum_findings + report.llm_findings if f.ran]
    for f in ran:
        print(ui.mark_run(f.command))
    print(ui.dim(f"  → 실행 {len(ran)}건"))

    stage(4, "3관문 작동 — 실행되지 않은 명령과 그 이유")
    blocked = [f for f in report.enum_findings + report.llm_findings
               if not f.ran and f.note.startswith("미승인")]
    for f in blocked:
        print(ui.mark_warn(f.command))
        print(ui.dim(f"     사유: {f.note}"))
    st = report.gate_stats
    print()
    print(ui.kv("제안", str(st["proposed"]), 15))
    print(ui.kv("실행", str(st["executed"]), 15))
    print(ui.kv("검토→수동강등", str(st["denied_review"]), 15))
    print(ui.kv("범위 밖 미실행", str(st["denied_scope"]), 15))
    print(ui.kv("검증/범위 오류", str(st["rejected_validate"] + st["rejected_scope"]), 15))
    print(ui.dim("  (무프롬프트 auto 모드 기준. 기본 모드에선 검토·범위 밖 명령을 사람에게 1회 확인)"))
    executed_risky = [c for c in runner.calls if "| bash" in c or OUT_OF_SCOPE in c]
    print((ui.mark_ok("검토 대상·범위 밖 명령 실제 실행 0건") if not executed_risky
           else ui.mark_err(f"예상과 다름: {executed_risky}")))

    stage(5, "지식 — 같은 완성형 지식으로 시작, 검증된 성장만 공유")
    k = report.knowledge
    if k:
        print(ui.kv("시작 지식", f"카탈로그 {k['catalog_covered']}/{k['catalog_topics']} 주제 · "
                                 f"번들 시드 {k['seed_topics']}개 (오프라인에서도 동일)", 10))
        print(ui.kv("승격 발췌", f"{k['promoted']}건 · 최근 {k['promoted_latest'] or '-'} "
                                 "(품질 관문 + 전체 테스트 통과분만)", 10))
    print(ui.kv("공유 흐름", "주간 자동 승격 → PR·자동 병합 → 실행 시 하루 1회 검증 동기화", 10))
    print(ui.dim("  공유 지식은 데이터(노트)만 · 코드는 받지 않음 · 검증 실패분은 버림"))

    stage(6, "산출 — 사람이 판단할 재료")
    cves = sorted(set(report.detected_cve) | {c for m in report.vuln_matches for c in m.cve})
    print(ui.kv("탐지 CVE", ", ".join(cves) or "(없음)", 10))
    print(ui.kv("수동 제안", f"{len(report.manual_suggestions)}건 (사람이 골라 승인)", 10))
    print(ui.kv("라이트업", "htb-ctf-writeup-v5 / Tistory 13섹션 자동 생성", 10))
    print(ui.dim("  전체 산출물: python3 scripts/demo.py --write OUT  (MD·JSON·HTML)"))
    print(ui.dim("  HTML 상단 '한눈에 보기'에 3관문 지표·플래그 출처·지식 기반·안전 경계가 요약됨"))

    print(ui.ok("\n라이브 데모 완료 — 실제 대상은 권한 확인된 환경의 Kali 에서 `assassin <target>`"))
    return 1 if executed_risky else 0


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if "--live" in argv:
        pace = 0.0
        if "--pace" in argv:
            i = argv.index("--pace")
            try:
                pace = max(0.0, float(argv[i + 1]))
            except (IndexError, ValueError):
                print(ui.mark_err("--pace 는 초 단위 숫자"))
                return 2
        return run_live(pace)
    write_dir = None
    if "--write" in argv:
        i = argv.index("--write")
        write_dir = argv[i + 1] if i + 1 < len(argv) else "."

    print(ui.banner("데모 — 네트워크/실도구 없이 전체 흐름 시연"))
    print(ui.dim(f"가상 타겟 {TARGET} · 공격자 {ATTACKER} · 실제 스캔/공격 없음\n"))

    report = build_demo_report()

    print(ui.rule("오케스트레이션 요약"))
    print(report.summary())

    htb_md = generate_writeup(report, attacker_ip=ATTACKER, machine_name="DemoBox")
    tis_md = generate_tistory(report, machine_name="DemoBox", attacker_ip=ATTACKER)

    if write_dir:
        os.makedirs(write_dir, exist_ok=True)
        hp = os.path.join(write_dir, "demo_writeup_htb.md")
        tp = os.path.join(write_dir, "demo_writeup_tistory.md")
        with open(hp, "w", encoding="utf-8") as f:
            f.write(htb_md)
        with open(tp, "w", encoding="utf-8") as f:
            f.write(tis_md)
        jp = os.path.join(write_dir, "demo_report.json")
        hpf = os.path.join(write_dir, "demo_report.html")
        with open(jp, "w", encoding="utf-8") as f:
            f.write(report_export.to_json(report))
        with open(hpf, "w", encoding="utf-8") as f:
            f.write(report_export.to_html(report, "DemoBox"))
        print(ui.ok(f"\n라이트업 저장: {hp} / {tp}"))
        print(ui.ok(f"구조화 결과 저장: {jp} / {hpf}"))
    else:
        print(ui.rule("HTB 라이트업 미리보기 (앞부분)"))
        print("\n".join(htb_md.splitlines()[:40]))
        print(ui.dim("\n... (전체는 --write <경로> 로 저장) ..."))

    print(ui.ok("\n데모 완료 — 실제 대상은 Kali 에서 `assassin <target>` (docs/OPERATIONS.md)"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
