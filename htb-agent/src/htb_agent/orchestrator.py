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
from .observation.parsers import NmapHost, parse_http
from .observation.compressor import profile_from_nmap
from .target_profiler import ProfileResult
from .knowledge import KnowledgeBase
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
    profile: ProfileResult | None = None
    enum_findings: list[EnumFinding] = field(default_factory=list)
    manual_suggestions: list[str] = field(default_factory=list)
    message: str = ""

    def summary(self) -> str:
        lines = [f"# 오케스트레이션 — {self.target} [{self.status}] {self.message}".rstrip()]
        if self.recon:
            lines.append("\n## RECON")
            lines.append(self.recon.summary())
        if self.profile:
            lines.append("\n## PROFILE")
            lines.append(self.profile.summary())
        if self.enum_findings:
            lines.append("\n## ENUM (자동실행)")
            for f in self.enum_findings:
                mark = "▶" if f.ran else "·"
                lines.append(f"  {mark} {f.command}" + (f"  — {f.note}" if f.note else ""))
                if f.output:
                    lines.append(f"      {f.output}")
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
                 is_tool_available: Callable[[str], bool] | None = None):
        self.guard = guard
        self.runner = runner
        self.kb = kb
        self.approver = approver
        self.hosts_map = hosts_map
        self.max_enum = max_enum
        self.recon_max_attempts = recon_max_attempts
        # 도구 설치 여부 판단(주입 가능 — 테스트에서 대체)
        self.is_tool_available = is_tool_available or (lambda b: shutil.which(b) is not None)

    def run(self) -> OrchestrationReport:
        if self.guard.bound_target is None:
            raise ScopeViolation("타겟 미바인딩 — bind_target() 먼저 호출하세요.")
        target = str(self.guard.bound_target)
        report = OrchestrationReport(target=target)

        # ── PHASE 1: RECON (유한 폴백) ──
        recon = ReconExecutor(self.guard, self.runner, self.approver,
                              max_attempts=self.recon_max_attempts,
                              hosts_map=self.hosts_map).run_portscan()
        report.recon = recon
        host = recon.host
        if host is None or not host.open_ports:
            report.status = "escalate"
            report.message = "열린 포트 미확보 — 다음 단계 불가. 사람 개입 필요."
            return report

        # ── PHASE 2: PROFILE ──
        prof = profile_from_nmap(host)
        report.profile = prof

        # ── PHASE 3: ENUM (KB 기반, 유한 상한) ──
        self._run_enum(report, host, prof, target)

        # ── PHASE 4: REPORT ──
        report.status = "done"
        report.message = f"OS={prof.os_class.value}({prof.tag}), enum {len(report.enum_findings)}건"
        return report

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
                self._attempt_enum(report, cmd)
                ran_count += 1

    def _attempt_enum(self, report: OrchestrationReport, cmd: str) -> None:
        finding = EnumFinding(command=cmd)
        report.enum_findings.append(finding)

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
        finding.output = self._summarize_output(cmd, out.stdout, out.stderr)

    @staticmethod
    def _summarize_output(cmd: str, stdout: str, stderr: str) -> str:
        if cmd.strip().startswith("curl") and "http" in cmd:
            h = parse_http(stdout)
            if h.status is not None:
                return h.summary()
        text = (stdout or stderr or "").strip()
        text = " ".join(text.split())
        return (text[:200] + "…") if len(text) > 200 else text
