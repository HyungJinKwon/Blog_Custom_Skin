"""
Orchestrator — 유한 단계 상태머신 (자동화 + 무한루프 금지)
==========================================================

단계(phase)를 '유한하게' 진행한다. 각 단계는 한 번씩(내부 폴백은 자체 상한)
실행되고, 다음 단계로 넘어간다. `while True` 없음 — 전체는 선형 파이프라인 +
각 단계의 유한 상한으로 구성된다.

  RECON   : 포트스캔(ReconExecutor, 유한 폴백)
  PROFILE : OS/역할 판정(Linux vs Windows-AD)
  ENUM    : 지식베이스(KB)로 다음 액션 선택 → 자동실행(승인 게이트 통과분, 상한)
  REPORT  : 자동실행 못 한 '수동' 제안 + 결과 요약

자동화이지만 실행은 승인제: 각 enum 명령도 검증→범위→승인 3관문을 통과해야
실행된다. 민감값({user}/{pass} 등)이 남은 제안은 자동실행하지 않고 수동 제안으로
남긴다.
"""

from __future__ import annotations

import shlex
import shutil
from dataclasses import dataclass, field
from typing import Callable

from .command_validator import validate, ValidationReport
from .scope_guard import ScopeGuard, ScopeViolation, CommandScopeResult
from .observation.parsers import NmapHost
from .observation.compressor import profile_from_nmap
from .observation.summarize import summarize_tool_output
from .target_profiler import ProfileResult
from .knowledge import KnowledgeBase
from .llm.router import LLMRouter
from .vuln import VulnKB, VulnMatch, extract_vuln_ids
from .state import SessionState, StateStore, host_to_dict, host_from_dict
from .tools.runner import Runner
from .tools.recon import ReconExecutor, ReconReport, auto_approve_in_scope, Approver


@dataclass
class EnumFinding:
    command: str
    ran: bool = False
    note: str = ""
    output: str = ""


@dataclass
class OrchestrationReport:
    target: str
    status: str = "pending"          # done / escalate
    recon: ReconReport | None = None
    host: NmapHost | None = None
    profile: ProfileResult | None = None
    enum_findings: list[EnumFinding] = field(default_factory=list)
    llm_findings: list[EnumFinding] = field(default_factory=list)
    manual_suggestions: list[str] = field(default_factory=list)
    detected_cve: list[str] = field(default_factory=list)
    detected_cwe: list[str] = field(default_factory=list)
    vuln_matches: list[VulnMatch] = field(default_factory=list)
    message: str = ""

    def summary(self) -> str:
        lines = [f"# 오케스트레이션 — {self.target} [{self.status}] {self.message}".rstrip()]
        if self.recon:
            lines.append("\n## RECON")
            lines.append(self.recon.summary())
        if self.profile:
            lines.append("\n## PROFILE")
            lines.append(self.profile.summary())
        for title, findings in (("ENUM (KB 자동실행)", self.enum_findings),
                                ("LLM 제안 (자동실행)", self.llm_findings)):
            if findings:
                lines.append(f"\n## {title}")
                for f in findings:
                    mark = "▶" if f.ran else "·"
                    lines.append(f"  {mark} {f.command}" + (f"  — {f.note}" if f.note else ""))
                    if f.output:
                        lines.append(f"      {f.output}")
        if self.detected_cve or self.detected_cwe or self.vuln_matches:
            lines.append("\n## VULN (탐지된 취약점 — 수동 검증/익스플로잇 필요)")
            if self.detected_cve:
                lines.append(f"  탐지 CVE: {', '.join(self.detected_cve)}")
            if self.detected_cwe:
                lines.append(f"  탐지 CWE: {', '.join(self.detected_cwe)}")
            for m in self.vuln_matches:
                sev = f"[{m.severity}] " if m.severity else ""
                ids = " ".join(m.cve + m.cwe)
                lines.append(f"  ⚠️ {sev}{m.name} ({ids}) — 매칭:{m.matched_on}")
                if m.note:
                    lines.append(f"       비고: {m.note}")
                for s in m.suggest:
                    lines.append(f"       제안: {s}")
        if self.manual_suggestions:
            lines.append("\n## 수동 제안 (크리덴셜 등 필요 — 승인/입력 후 실행)")
            for s in self.manual_suggestions:
                lines.append(f"  · {s}")
        return "\n".join(lines)


def _binary_of(command: str) -> str:
    try:
        toks = shlex.split(command)
    except ValueError:
        toks = command.split()
    for t in toks:
        if "=" in t and not t.startswith("-"):
            continue
        return t
    return ""


class Orchestrator:
    def __init__(self, guard: ScopeGuard, runner: Runner, kb: KnowledgeBase,
                 approver: Approver = auto_approve_in_scope,
                 hosts_map: dict[str, str] | None = None,
                 max_enum: int = 6,
                 recon_max_attempts: int = 4,
                 llm_router: LLMRouter | None = None,
                 max_llm: int = 5,
                 vuln_kb: VulnKB | None = None,
                 state_store: StateStore | None = None,
                 resume: bool = False,
                 is_tool_available: Callable[[str], bool] | None = None):
        self.guard = guard
        self.runner = runner
        self.kb = kb
        self.approver = approver
        self.hosts_map = hosts_map
        self.max_enum = max_enum
        self.recon_max_attempts = recon_max_attempts
        self.llm_router = llm_router
        self.max_llm = max_llm
        self.vuln_kb = vuln_kb
        self.state_store = state_store
        self.resume = resume
        # 도구 설치 여부 판단(주입 가능 — 테스트에서 대체)
        self.is_tool_available = is_tool_available or (lambda b: shutil.which(b) is not None)

    def run(self) -> OrchestrationReport:
        if self.guard.bound_target is None:
            raise ScopeViolation("타겟 미바인딩 — bind_target() 먼저 호출하세요.")
        target = str(self.guard.bound_target)
        report = OrchestrationReport(target=target)

        # 재개: 저장된 상태에 포트가 있으면 RECON 을 건너뛰고 재사용
        prior: SessionState | None = None
        host = None
        if self.resume and self.state_store and self.state_store.exists(target):
            prior = self.state_store.load(target)
            if prior and prior.host:
                host = host_from_dict(prior.host)
                report.message = "(재개: 저장된 RECON 재사용 — 재스캔 생략) "

        # ── PHASE 1: RECON (유한 폴백) — 재개로 host 확보 시 생략 ──
        if host is None:
            recon = ReconExecutor(self.guard, self.runner, self.approver,
                                  max_attempts=self.recon_max_attempts,
                                  hosts_map=self.hosts_map).run_portscan()
            report.recon = recon
            host = recon.host
        report.host = host
        if host is None or not host.open_ports:
            report.status = "escalate"
            report.message += "열린 포트 미확보 — 다음 단계 불가. 사람 개입 필요."
            self._persist(report, prior)
            return report

        # ── PHASE 2: PROFILE ──
        prof = profile_from_nmap(host)
        report.profile = prof

        # ── PHASE 3: ENUM (KB 기반, 유한 상한) ──
        self._run_enum(report, host, prof, target)

        # ── PHASE 3.5: LLM 제안 (선택, 유한 상한) ──
        if self.llm_router is not None:
            self._run_llm(report, host, prof, target)

        # ── PHASE 3.7: VULN (CVE/CWE 탐지 + 매핑) ──
        self._run_vuln(report, host, target)

        # ── PHASE 4: REPORT ──
        report.status = "done"
        report.message += (f"OS={prof.os_class.value}({prof.tag}), "
                           f"KB enum {len(report.enum_findings)}건, "
                           f"LLM {len(report.llm_findings)}건")
        self._persist(report, prior)
        return report

    def _persist(self, report: OrchestrationReport, prior: SessionState | None) -> None:
        """진행 상태를 저장(중단/재개용). state_store 없으면 no-op."""
        if self.state_store is None:
            return
        st = prior or SessionState(target=report.target)
        st.allowed_ranges = [str(n) for n in self.guard.allowed_target_cidrs]
        st.attacker_ips = [str(ip) for ip in self.guard.attacker_ips]
        st.recon_status = report.recon.status if report.recon else (st.recon_status or "resumed")
        if report.host is not None:
            st.host = host_to_dict(report.host)
        if report.profile is not None:
            st.profile = {"os_class": report.profile.os_class.value,
                          "confidence": report.profile.confidence,
                          "is_dc": report.profile.is_domain_controller}
        fin = lambda f: {"command": f.command, "ran": f.ran, "note": f.note, "output": f.output}
        if report.enum_findings:
            st.enum_findings = [fin(f) for f in report.enum_findings]
        if report.llm_findings:
            st.llm_findings = [fin(f) for f in report.llm_findings]
        if report.manual_suggestions:
            st.manual_suggestions = report.manual_suggestions
        if report.detected_cve:
            st.detected_cve = report.detected_cve
        if report.detected_cwe:
            st.detected_cwe = report.detected_cwe
        st.add_history(report.message.strip() or report.status)
        self.state_store.save(st)

    def _run_enum(self, report: OrchestrationReport, host: NmapHost,
                  prof: ProfileResult, target: str) -> None:
        services = [p.service for p in host.ports if p.state == "open" and p.service]
        recs = self.kb.query(prof.os_class.value, host.open_ports, services)

        seen: set[str] = set()
        ran_count = 0
        for rec in recs:
            for tmpl in rec.suggestions:
                cmd, auto_runnable = self.kb.format_suggestion(tmpl, target)
                if cmd in seen:
                    continue
                seen.add(cmd)
                if not auto_runnable:
                    report.manual_suggestions.append(cmd + f"   # [{rec.rule_name}]")
                    continue
                if ran_count >= self.max_enum:     # 유한 상한 — 무한 확장 방지
                    report.manual_suggestions.append(cmd + "   # (enum 상한 초과 — 수동)")
                    continue
                self._attempt(report.enum_findings, cmd)
                ran_count += 1

    def _run_llm(self, report: OrchestrationReport, host: NmapHost,
                 prof: ProfileResult, target: str) -> None:
        services = [p.service for p in host.ports if p.state == "open" and p.service]
        recs = self.kb.query(prof.os_class.value, host.open_ports, services)
        context = {
            "profile": prof.summary(),
            "open_ports": [str(p) for p in host.ports if p.state == "open"],
            "kb": [f"{r.rule_name}: {', '.join(r.suggestions)}" for r in recs[:5]],
            "notes": self.kb.notes[:3],
        }
        try:
            cmds = self.llm_router.suggest_commands(context, target, max_items=self.max_llm)
        except Exception as e:  # LLM 백엔드 오류는 전체를 깨지 않는다
            report.manual_suggestions.append(f"(LLM 제안 실패: {e})")
            return
        seen = {f.command for f in report.enum_findings}
        for cmd in cmds[:self.max_llm]:     # 유한 상한
            if cmd in seen:
                continue
            seen.add(cmd)
            self._attempt(report.llm_findings, cmd)

    def _run_vuln(self, report: OrchestrationReport, host: NmapHost, target: str) -> None:
        # 관측 코퍼스: 배너 + 스크립트 + enum/LLM 출력
        corpus_parts = list(host.hostscripts.values())
        banners: list[str] = []
        for p in host.ports:
            if p.state == "open":
                if p.banner:
                    banners.append(p.banner)
                    corpus_parts.append(p.banner)
                corpus_parts.extend(p.scripts.values())
        for f in report.enum_findings + report.llm_findings:
            if f.output:
                corpus_parts.append(f.output)
        hits = extract_vuln_ids("\n".join(corpus_parts))
        report.detected_cve = hits.cves
        report.detected_cwe = hits.cwes
        if self.vuln_kb is not None:
            report.vuln_matches = self.vuln_kb.match(banners, target)

    def _attempt(self, findings: list[EnumFinding], cmd: str) -> None:
        finding = EnumFinding(command=cmd)
        findings.append(finding)

        binary = _binary_of(cmd)
        if binary and not self.is_tool_available(binary):
            finding.note = f"건너뜀: '{binary}' 미설치"
            return
        vrep: ValidationReport = validate(cmd)
        if not vrep.ok:
            finding.note = "검증 실패: " + "; ".join(str(i) for i in vrep.errors)
            return
        try:
            sres: CommandScopeResult = self.guard.inspect_command(cmd, hosts_map=self.hosts_map)
        except ScopeViolation as e:
            finding.note = f"범위 오류: {e}"
            return
        if not self.approver(cmd, vrep, sres):
            finding.note = "미승인(범위밖/사용자 거부)"
            return

        out = self.runner.run(cmd, timeout=180)
        finding.ran = out.launched
        if not out.launched:
            finding.note = f"실행 실패: {out.error}"
            return
        finding.output = summarize_tool_output(cmd, out.stdout, out.stderr)
