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

주의: 이 스크립트는 네트워크를 쓰지 않는다. 실제 대상 공격은 권한이 확인된
      환경의 Kali 에서 `assassin <target>` 으로 수행한다(docs/OPERATIONS.md).
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from htb_agent import ui  # noqa: E402
from htb_agent.scope_guard import ScopeGuard  # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput  # noqa: E402
from htb_agent.tools.recon import auto_approve_in_scope  # noqa: E402
from htb_agent.knowledge import KnowledgeBase  # noqa: E402
from htb_agent.vuln import VulnKB  # noqa: E402
from htb_agent.enrich import Enricher  # noqa: E402
from htb_agent.orchestrator import Orchestrator  # noqa: E402
from htb_agent.llm.router import LLMRouter  # noqa: E402
from htb_agent.llm.fake_provider import FakeProvider  # noqa: E402
from htb_agent.writeup import generate_writeup, generate_tistory  # noqa: E402

TARGET = "10.129.10.10"
ATTACKER = "10.10.14.7"

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


def build_demo_report():
    """데모용 OrchestrationReport 를 네트워크 없이 생성(테스트에서도 재사용)."""
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
    llm = LLMRouter(FakeProvider(
        lambda s, u, t: "curl -i http://{t}/robots.txt\ngobuster dir -u http://{t} -w common.txt"
        .replace("{t}", TARGET)))
    enricher = Enricher(cache_dir=os.path.join("/tmp", "assassin_demo_cache"),
                        fetch_fn=_canned_fetch, enabled=True, want_poc=True)

    orch = Orchestrator(
        guard, runner, KnowledgeBase.load(), auto_approve_in_scope,
        vuln_kb=VulnKB.load(), llm_router=llm, enricher=enricher,
        is_tool_available=lambda b: True)
    return orch.run()


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
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
        print(ui.ok(f"\n라이트업 저장: {hp} / {tp}"))
    else:
        print(ui.rule("HTB 라이트업 미리보기 (앞부분)"))
        print("\n".join(htb_md.splitlines()[:40]))
        print(ui.dim("\n... (전체는 --write <경로> 로 저장) ..."))

    print(ui.ok("\n데모 완료 — 실제 대상은 Kali 에서 `assassin <target>` (docs/OPERATIONS.md)"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
