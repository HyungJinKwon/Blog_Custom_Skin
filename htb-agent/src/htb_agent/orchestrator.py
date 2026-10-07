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

import re
import shutil
from dataclasses import dataclass, field
from typing import Callable

from .util import binary_of
from .command_validator import validate, ValidationReport
from .scope_guard import ScopeGuard, ScopeViolation, CommandScopeResult
from .observation.parsers import NmapHost
from .observation.compressor import profile_from_nmap
from .observation.summarize import summarize_tool_output
from .target_profiler import ProfileResult
from .knowledge import KnowledgeBase
from .creds import CredentialVault
from .audit import NullAudit
from .llm.router import LLMRouter
from .vuln import VulnKB, VulnMatch, extract_vuln_ids
from .flag import FlagHit, scan as scan_flags
from .crack import scan_hashes as crack_scan
from .creds_harvest import harvest as harvest_creds, is_safe_for_cmd
from . import diagnostics
from . import provenance as _prov
from .world import WorldModel
from .variants import expand_variants, fragment_of
from .state import SessionState, StateStore, host_to_dict, host_from_dict
from .tools.runner import Runner, RunOutput
from .tools.recon import ReconExecutor, ReconReport, auto_approve_in_scope, Approver


# 모의해킹 진행 단계(순서대로). (key, 표시라벨)
PENTEST_PHASES: list[tuple[str, str]] = [
    ("enum", "열거 (Enumeration)"),
    ("access", "초기 침투 (Initial Access)"),
    ("privesc", "권한 상승 (Privilege Escalation)"),
    ("lateral", "측면 이동 (Lateral Movement)"),
]
_PHASE_LABEL = dict(PENTEST_PHASES)


@dataclass
class EnumFinding:
    command: str
    ran: bool = False
    note: str = ""
    output: str = ""
    phase: str = "enum"
    skipped: bool = False   # 도구 미설치로 시도조차 안 함 — 예산(max_enum/max_llm)을 쓰지 않는다


GATE_KEYS = ("proposed", "executed", "run_failed", "tool_missing", "rejected_validate",
             "rejected_scope", "denied_review", "denied_scope")


def _new_gate_stats() -> dict:
    return {k: 0 for k in GATE_KEYS}


@dataclass
class OrchestrationReport:
    target: str
    status: str = "pending"          # pending / done / escalate / interrupted
    recon: ReconReport | None = None
    host: NmapHost | None = None
    profile: ProfileResult | None = None
    world: "WorldModel | None" = None  # world.WorldModel — 구조화 상태(단일 상태원)
    analysis: str = ""                # LLM 분석가(B3) — 가설·공격경로·다음집중·확신도
    phase_status: dict = field(default_factory=dict)   # A2 단계 게이팅 상태(phase→상태)
    # 3관문 결과 집계(열거·LLM 명령 기준, 정찰 포트스캔 제외) — 리포트·대시보드용
    gate_stats: dict = field(default_factory=_new_gate_stats)
    enum_findings: list[EnumFinding] = field(default_factory=list)
    llm_findings: list[EnumFinding] = field(default_factory=list)
    manual_suggestions: list[str] = field(default_factory=list)
    detected_cve: list[str] = field(default_factory=list)
    detected_cwe: list[str] = field(default_factory=list)
    vuln_matches: list[VulnMatch] = field(default_factory=list)
    flags: list[FlagHit] = field(default_factory=list)
    flag_kind: str = "boot2root"     # boot2root(user/root) | single(CTF flag)
    enriched: list = field(default_factory=list)   # list[enrich.CveInfo]
    # 자동 준비된 리버스쉘 페이로드(공격자 IP 확보 시 자동 생성 — 생성만, 실행 안 함)
    revshells: list = field(default_factory=list)   # list[revshell.RevShell]
    revshell_lhost: str = ""
    revshell_lport: int = 0
    # 자동 준비된 AWS/S3 열거(호스트명/도메인 확보 시 — 생성만, AWS 는 범위 밖·실행 안 함)
    cloud_candidates: list = field(default_factory=list)   # list[str] 버킷 후보
    cloud_checks: list = field(default_factory=list)       # list[cloud.CloudCheck]
    # 자동 준비된 권한상승 플레이북(OS 식별 시 — 생성만, 대상 셸에서 사용자 실행)
    privesc_steps: list = field(default_factory=list)      # list[privesc.PrivescStep]
    privesc_cve_candidates: list = field(default_factory=list)  # list[str]
    # 자동 준비된 해시 크래킹 작업(출력/볼트에서 해시 수집 시 — 생성만, 사용자 실행)
    crack_jobs: list = field(default_factory=list)         # list[crack.CrackJob]
    # 자율 지식 획득(모르는 기술 → 권위 출처에서 자동 학습, P1 유지)
    acquired_knowledge: list = field(default_factory=list)  # "용어 → 주제 (출처)"
    knowledge_gaps: list = field(default_factory=list)      # 미해석 공백(수동 조사 필요)
    # 지식 기반 현황(번들 시드·승격·공유 동기화) — kb_sync.knowledge_summary, main 이 채움
    knowledge: dict = field(default_factory=dict)
    # 실패 진단(사람 확인용) — (command, FailureDiagnosis) 목록. 자동 재공격 아님
    blockers: list = field(default_factory=list)
    # 플래그 출처 검증(실행 트레이스 기반) — list[provenance.FlagProvenance]
    flag_provenance: list = field(default_factory=list)
    goal_reached: bool = False        # 신뢰 가능한 플래그로 목표 달성 → 남은 단계 조기 종료
    # LLM 라우팅 집계(하이브리드일 때 main 이 채움): 로컬/강력/폴백/거절/빈응답/오류/미응답 + 차단 백엔드
    llm_routing: dict = field(default_factory=dict)
    message: str = ""

    @property
    def user_flag(self) -> str | None:
        return next((f.value for f in self.flags if f.kind == "user"), None)

    @property
    def root_flag(self) -> str | None:
        return next((f.value for f in self.flags if f.kind == "root"), None)

    def summary(self) -> str:
        from . import ui
        st = ui.ok if self.status == "done" else ui.accent2
        head = (ui.accent("ASSASSIN") + ui.dim(" · 오케스트레이션 ")
                + ui.bold(self.target) + "  " + st(f"[{self.status}]")
                + (("  " + ui.dim(self.message)) if self.message else ""))
        lines = [head, ui.rule("", 60, "navy")]
        if self.recon:
            lines.append(ui.heading("RECON", "📡"))
            lines.append(self.recon.summary())
        if self.profile:
            lines.append("\n" + ui.heading("PROFILE", "🧭"))
            lines.append(self.profile.summary())
        if self.world is not None:
            lines.append("\n" + ui.heading("STATE  (월드 모델 — 구조화 상태)", "🗺️"))
            lines.append(self.world.summary())
        if self.analysis:
            lines.append("\n" + ui.heading("ANALYSIS  (LLM 분석 — 병렬 가설·계획·경로)", "🧠"))
            for ln in self.analysis.splitlines():
                if ln.strip():
                    lines.append("  " + ui.dim(ln.strip()))
        if self.acquired_knowledge or self.knowledge_gaps:
            lines.append("\n" + ui.heading(
                "LEARN  (자율 지식 획득 — 권위 출처만, P1 유지)", "🎓"))
            for a in self.acquired_knowledge:
                lines.append("  " + ui.ok("학습") + " " + a)
            for g in self.knowledge_gaps:
                lines.append("  " + ui.dim("미해석 공백(수동 조사): ") + g)
        # 모의해킹 단계 순서대로 그룹화 출력
        all_findings = self.enum_findings + self.llm_findings
        for key, label in PENTEST_PHASES:
            group = [f for f in all_findings if f.phase == key]
            st_label = self.phase_status.get(key, "")
            if group or st_label:
                suffix = ("  " + ui.dim(f"[{st_label}]")) if st_label else ""
                lines.append("\n" + ui.rule(f"단계: {label}{suffix}", 60))
            for f in group:
                mark = ui.mark_run() if f.ran else ui.dim("·")
                note = ui.dim(f"  — {f.note}") if f.note else ""
                lines.append(f"  {mark} {f.command}{note}")
                if f.output:
                    lines.append("      " + ui.dim(f.output))
        if self.blockers:
            from . import diagnostics as _diag
            lines.append("\n" + ui.heading(
                "BLOCKERS  (막힌 지점 — 사람 확인용. 자동 재공격 아님)", "🧯"))
            diags = [d for _, d in self.blockers]
            tgt = [(c, d) for c, d in self.blockers if d.is_target]
            env = [(c, d) for c, d in self.blockers if not d.is_target]
            if tgt:
                lines.append("  " + ui.accent2("대상 응답(경로 판단에 유효):"))
                for cmd, d in tgt[:8]:
                    lines.append(f"    · {d.label}  — {ui.dim(cmd[:60])}")
                    if d.hint:
                        lines.append("      " + ui.dim("↳ " + d.hint))
            if env:
                lines.append("  " + ui.accent2("환경/도구/네트워크(경로 실패 아님):"))
                for cmd, d in env[:8]:
                    lines.append(f"    · {d.label}  — {ui.dim(cmd[:60])}")
                    if d.hint:
                        lines.append("      " + ui.dim("↳ " + d.hint))
            # 오판 방지: '대상이 거듭 거부'한 범주만 경로 재검토 후보로 '표시'(결정은 사람)
            signals = _diag.abandonment_signals(diags)
            repeated = {c: n for c, n in signals.items() if n >= 2}
            if repeated:
                lines.append("  " + ui.warn("경로 재검토 후보(대상이 2회+ 거부): ")
                             + ", ".join(f"{c}×{n}" for c, n in repeated.items())
                             + ui.dim("  — 환경 문제는 제외됨. 포기 여부는 사람이 판단."))
        from . import repetition as _rep
        _rr = _rep.analyze(self.enum_findings + self.llm_findings, self.blockers)
        if _rr.has_findings:
            lines.append("\n" + ui.heading(
                "REPETITION  (반복·정체 감지 — 사람 확인용. 자동 재계획 아님)", "🔁"))
            for sig, n in _rr.repeated_cmds[:6]:
                lines.append("  " + ui.warn(f"반복 명령 ×{n}: ") + ui.dim(sig))
            for cat, n in _rr.repeated_failures[:6]:
                lines.append("  " + ui.warn(f"같은 실패 ×{n}: ") + ui.dim(cat))
            if _rr.stalled:
                lines.append("  " + ui.warn("정체: ")
                             + ui.dim("실행은 여러 번이나 유의미한 출력이 희박 — 다른 각도를 사람이 검토"))
        if self.flag_provenance:
            lines.append("\n" + ui.heading(
                "PROVENANCE  (플래그 출처 검증 — 실행 트레이스 기반)", "🔎"))
            for p in self.flag_provenance:
                pmark = ui.ok if p.verdict == "exploit-derived" else ui.warn
                lines.append("  " + pmark(f"[{p.label}] ") + f"{p.kind} flag")
                lines.append("      " + ui.dim(f"↳ {p.reason} · {p.command[:60]}"))
            susp = [p for p in self.flag_provenance if p.verdict != "exploit-derived"]
            if susp:
                lines.append("  " + ui.warn(
                    f"※ {len(susp)}건은 공략 유래가 아닐 수 있음 — 사람이 실제 공략 경로 확인"))
        from . import recommend as _recommend
        _recs = _recommend.propose(self, repetition=_rr)   # 반복 분석 1회만
        if _recs.has_items:
            lines.append("\n" + ui.heading(
                "NEXT OPTIONS  (다음 선택지 — 사람이 골라 승인. 자동 실행 아님)", "🧭"))
            for i, r in enumerate(_recs.items, 1):
                lines.append(f"  {ui.accent2(str(i) + '.')} {r.title}")
                lines.append("      " + ui.dim("근거: " + r.rationale))
                if r.ref:
                    lines.append("      " + ui.dim("참고: " + r.ref[:72]))
            lines.append("  " + ui.dim("→ 번호를 골라 해당 명령/각도를 승인하면 3관문을 거쳐 실행됩니다."))
        if self.detected_cve or self.detected_cwe or self.vuln_matches:
            lines.append("\n" + ui.heading(
                "VULN  (탐지된 취약점 — 수동 검증/익스플로잇 필요)", "🛑"))
            if self.detected_cve:
                lines.append(ui.kv("탐지 CVE", ui.warn(", ".join(self.detected_cve)), 9))
            if self.detected_cwe:
                lines.append(ui.kv("탐지 CWE", ui.warn(", ".join(self.detected_cwe)), 9))
            for m in self.vuln_matches:
                sev = f"[{m.severity}] " if m.severity else ""
                ids = " ".join(m.cve + m.cwe)
                lines.append("  " + ui.mark_warn(
                    ui.warn(sev) + m.name + ui.dim(f" ({ids}) — 매칭:{m.matched_on}")))
                if m.note:
                    lines.append(ui.dim(f"       비고: {m.note}"))
                for s in m.suggest:
                    lines.append("       " + ui.accent2("제안: ") + s)
        if self.enriched:
            lines.append("\n" + ui.heading("CVE 레퍼런스 (자동 수집 — NVD/GitHub)", "📚"))
            for e in self.enriched:
                sev = f"[{e.severity} {e.cvss}] " if e.severity else ""
                lines.append("  " + ui.warn(sev) + ui.bold(e.id)
                             + (ui.dim("  " + ", ".join(e.cwe)) if e.cwe else ""))
                if e.description:
                    lines.append(ui.dim("     " + e.description[:160]))
                for r in e.references[:3]:
                    lines.append("     " + ui.accent2("ref: ") + ui.dim(r))
                for p in e.poc_repos[:3]:
                    lines.append("     " + ui.accent2("PoC: ") + ui.dim(p))
        if self.flags:
            lines.append("\n" + ui.heading("🚩 플래그 (FLAG)"))
            if self.flag_kind == "single":
                for fh in self.flags:
                    lines.append("  " + ui.flag(fh.value)
                                 + ui.dim(f"  ← {fh.source}"))
            else:
                uf = ui.flag(self.user_flag) if self.user_flag else ui.dim("미획득")
                rf = ui.flag(self.root_flag) if self.root_flag else ui.dim("미획득")
                lines.append("  " + ui.dim("user.txt:") + " " + uf)
                lines.append("  " + ui.dim("root.txt:") + " " + rf)
                for fh in self.flags:
                    if fh.kind == "unknown":
                        lines.append(ui.dim(f"  (미분류) {fh.value} ← {fh.source}"))
        if self.revshells:
            from .revshell import listener_hints
            lines.append("\n" + ui.heading(
                "리버스쉘 (자동 준비 — 초기 침투용 · 생성만, 에이전트는 실행 안 함)", "🐚"))
            lines.append(ui.dim(
                f"  LHOST={self.revshell_lhost}  LPORT={self.revshell_lport}"
                "  ·  권한 확인 대상에서 사용자가 직접 실행"))
            lines.append("  " + ui.accent2("리스너: ") + listener_hints(self.revshell_lport)[0])
            for s in self.revshells:
                lines.append("  " + ui.accent2(f"[{s.name}]"))
                lines.append("    " + s.payload)
        if self.cloud_checks:
            lines.append("\n" + ui.heading(
                "AWS/S3 열거 (자동 준비 — 생성만, AWS 는 범위 밖·실행 안 함)", "☁️"))
            if self.cloud_candidates:
                lines.append(ui.dim(
                    f"  버킷 후보({len(self.cloud_candidates)}): "
                    + ", ".join(self.cloud_candidates[:12])
                    + (" …" if len(self.cloud_candidates) > 12 else "")))
            for c in self.cloud_checks:
                lines.append("  " + ui.accent2(f"[{c.name}] ") + c.command)
        if self.privesc_steps:
            lines.append("\n" + ui.heading(
                "권한 상승 플레이북 (자동 준비 — 대상 셸에서 실행 · 생성만)", "⬆️"))
            for s in self.privesc_steps:
                lines.append("  " + ui.accent2(f"[{s.category}] ") + s.command)
                if s.note:
                    lines.append(ui.dim("      " + s.note))
            for c in self.privesc_cve_candidates:
                lines.append("  " + ui.mark_warn(ui.warn("LPE 후보: ") + c))
        if self.crack_jobs:
            lines.append("\n" + ui.heading(
                "해시 크래킹 (자동 준비 — 생성만, 사용자 환경에서 실행)", "🔑"))
            for j in self.crack_jobs:
                gnames = ", ".join(g.name for g in j.guesses) or "미상"
                lines.append("  " + ui.accent2("해시: ") + ui.dim(j.hash[:64]
                             + ("…" if len(j.hash) > 64 else "")))
                lines.append("    " + ui.dim(f"식별: {gnames}"))
                for c in j.commands:
                    lines.append("    " + ui.accent2(f"[{c.tool}] ") + c.command)
        if self.manual_suggestions:
            lines.append("\n" + ui.heading(
                "수동 제안 (크리덴셜 등 필요 — 승인/입력 후 실행)", "✋"))
            for s in self.manual_suggestions:
                lines.append(ui.bullet(s, "·", "dim"))
        return "\n".join(lines)


class Orchestrator:
    def __init__(self, guard: ScopeGuard, runner: Runner, kb: KnowledgeBase,
                 approver: Approver = auto_approve_in_scope,
                 hosts_map: dict[str, str] | None = None,
                 max_enum: int = 6,
                 recon_max_attempts: int = 4,
                 max_rounds: int = 2,
                 max_sweeps: int = 2,
                 max_variants: int = 1,
                 llm_router: LLMRouter | None = None,
                 max_llm: int = 5,
                 vuln_kb: VulnKB | None = None,
                 vault: CredentialVault | None = None,
                 state_store: StateStore | None = None,
                 resume: bool = False,
                 audit=None,
                 phases: list[tuple[str, str]] | None = None,
                 flag_kind: str = "boot2root",
                 flag_prefixes: tuple[str, ...] = (),
                 enricher=None,
                 platform_name: str = "Hack The Box",
                 category: str = "",
                 revshell_port: int = 4444,
                 variant_stats=None,
                 max_parallel: int = 1,
                 learner=None,
                 learn_gaps: bool = False,
                 max_gap_learn: int = 6,
                 web_learner=None,
                 is_tool_available: Callable[[str], bool] | None = None):
        self.guard = guard
        self.runner = runner
        self.kb = kb
        self.approver = approver
        self.hosts_map = hosts_map
        self.max_enum = max_enum
        self.recon_max_attempts = recon_max_attempts
        self.max_rounds = max(1, max_rounds)
        self.max_sweeps = max(1, max_sweeps)
        self.max_variants = max(1, max_variants)
        self.llm_router = llm_router
        self.max_llm = max_llm
        self.vuln_kb = vuln_kb
        self.vault = vault
        self.state_store = state_store
        self.resume = resume
        self.audit = audit or NullAudit()
        self.phases = phases or PENTEST_PHASES
        self.flag_kind = flag_kind
        self.flag_prefixes = flag_prefixes
        self.platform_name = platform_name
        self.category = category
        self.revshell_port = revshell_port
        self.variant_stats = variant_stats   # 실행 결과 기반 변형 학습(없으면 미학습)
        self.max_parallel = max(1, max_parallel)   # 열거 동시 실행 수(1=순차)
        self.enricher = enricher
        # 자율 지식 획득 — 모르는 기술을 권위 출처에서 자동 학습(learner 주입 시)
        self.learner = learner
        self.learn_gaps = learn_gaps
        self.max_gap_learn = max(0, max_gap_learn)
        self.web_learner = web_learner   # 인터넷 검색 학습(HTB 라이트업 가드) — 미해석 공백용
        self._acquired_topics: set[str] = set()   # 세션 내 중복 학습 방지
        # 도구 설치 여부 판단(주입 가능 — 테스트에서 대체)
        self.is_tool_available = is_tool_available or (lambda b: shutil.which(b) is not None)

    def run(self) -> OrchestrationReport:
        if self.guard.bound_target is None and self.guard.bound_host is None:
            raise ScopeViolation("타겟 미바인딩 — bind_target() 먼저 호출하세요.")
        target = str(self.guard.bound_target or self.guard.bound_host)
        report = OrchestrationReport(target=target, flag_kind=self.flag_kind)
        # 구조화 상태(월드 모델) — 파이프라인·LLM·리포트의 단일 상태원
        self.world = WorldModel(target=target,
                                hostname=(self.hosts_map or {}).get(target, ""))
        report.world = self.world
        if self.vault is not None:
            for c in self.vault.creds:
                sec = c.password or c.nt_hash or ""
                self.world.add_cred(f"{c.username}:{sec}" if sec else c.username)
        self._found_hashes: list[str] = []   # 실행 원시출력에서 수집한 크래킹 대상 해시
        self.audit.event("session_start", target=target, resume=self.resume,
                         ranges=[str(n) for n in self.guard.allowed_target_cidrs])

        # 재개: 저장된 상태에 포트가 있으면 RECON 을 건너뛰고 재사용
        prior: SessionState | None = None
        host = None
        seen_cmds: set[str] = set()
        if self.resume and self.state_store and self.state_store.exists(target):
            prior = self.state_store.load(target)
            if prior and prior.host:
                host = host_from_dict(prior.host)
                report.message = "(재개: 저장된 RECON 재사용 — 재스캔 생략) "
            if prior:
                self._restore(report, prior, seen_cmds)
        # 예산은 '이번 실행' 기준(재개로 복원한 이전 결과는 예산을 쓰지 않음)
        self._enum_base = len(report.enum_findings)
        self._llm_base = len(report.llm_findings)

        # ── PHASE 1: RECON (유한 폴백) — 재개로 host 확보 시 생략 ──
        if host is None:
            recon = ReconExecutor(self.guard, self.runner, self.approver,
                                  max_attempts=self.recon_max_attempts,
                                  hosts_map=self.hosts_map).run_portscan()
            report.recon = recon
            host = recon.host
        report.host = host
        self.audit.event("recon", status=(report.recon.status if report.recon else "resumed"),
                         open_ports=host.open_ports if host else [])
        if host is None or not host.open_ports:
            report.status = "escalate"
            report.message += "열린 포트 미확보 — 다음 단계 불가. 사람 개입 필요."
            self._persist(report, prior)
            self.audit.event("session_end", status=report.status, message=report.message)
            return report

        # ── PHASE 2: PROFILE ──
        prof = profile_from_nmap(host)
        report.profile = prof
        self.world.set_profile(host, prof)   # 호스트/서비스/OS 상태 반영
        self.audit.event("profile", os=prof.os_class.value, confidence=prof.confidence,
                         is_dc=prof.is_domain_controller)

        # ── PHASE 3: 모의해킹 단계 '순서대로' 진행 (유한 반복·재진입 스윕) ──
        # enum → access → privesc → lateral 순. 각 단계는 KB(해당 phase)+LLM 적응
        # 라운드를 돌린다. 한 스윕(전 단계 1회 통과) 뒤 '월드 상태가 성장'하면
        # (새 관측·크리덴셜·서비스로 이전 단계가 다시 유효해지면) 다음 스윕을 돈다.
        # 전역 상한(max_enum·max_llm)·명령 중복제거(seen_cmds)·상태정체 조기종료로 유한.
        phases_run: list[str] = []
        sweeps_run = 0
        self._analysis_fp: tuple | None = None
        interrupted = False
        try:
            for sweep in range(self.max_sweeps):
                if self._goal_reached(report):
                    break
                before_fp = self._world_fingerprint(report)
                # 지금까지의 출력에서 취약점(CVE/CWE·버전 매칭)을 먼저 반영 — 학습·분석·
                # 명령 생성이 '확인 취약점'을 보고 판단하도록(이전엔 루프가 끝난 뒤에야 계산)
                self._run_vuln(report, host, target)
                # 자율 지식 획득: 관측된 기술 중 '모르는 것'을 권위 출처에서 자동 학습해
                # KB 에 즉시 반영한다(이후 분석가·명령생성이 바로 활용). P1 유지.
                self._acquire_knowledge(report, host, prof)
                for key, label in self.phases:
                    if self._goal_reached(report):
                        report.phase_status.setdefault(key, "생략(목표 달성)")
                        continue
                    # A2 단계 게이팅: 전제(권한레벨/크리덴셜) 미충족 단계는 KB 가이드(수동
                    # 제안)는 남기되 투기적 LLM 라운드는 건너뛴다(상태가 자라면 다음 스윕서 활성).
                    met, reason = self._prereq_met(key)
                    # B3 분석가: 이 단계의 명령 생성 직전에, 마지막 분석 이후 상태가 자랐을
                    # 때만 다시 판단한다(앞 단계 결과·새 크리덴셜·취약점을 계획에 반영).
                    if met and self.llm_router is not None:
                        self._refresh_analysis(report, prof, host, target)
                    phase_before = len(report.enum_findings) + len(report.llm_findings)
                    for _rnd in range(self.max_rounds):
                        added = self._enum_round(
                            report, host, prof, target, seen_cmds,
                            self.max_enum - self._spent(report.enum_findings, self._enum_base),
                            key)
                        if met and self.llm_router is not None and not self._goal_reached(report):
                            added += self._llm_round(
                                report, host, prof, target, seen_cmds,
                                self.max_llm - self._spent(report.llm_findings, self._llm_base),
                                key)
                        if added == 0 or self._goal_reached(report):
                            break
                    grew = len(report.enum_findings) + len(report.llm_findings) > phase_before
                    if grew and key not in phases_run:
                        phases_run.append(key)
                    # 한 번이라도 '진행'한 단계는 이후 스윕에서 새 명령이 없어도 '진행' 유지
                    if report.phase_status.get(key) != "진행":
                        report.phase_status[key] = ("대기(" + reason + ")" if not met
                                                    else ("진행" if grew else "점검함"))
                    self._run_vuln(report, host, target)   # 다음 단계가 새 취약점을 보도록
                sweeps_run += 1
                # 이번 스윕에서 상태가 더 자라지 않았으면(새 관측·예산 소진) 조기 종료 — 유한
                if self._world_fingerprint(report) == before_fp:
                    break
        except KeyboardInterrupt:
            # 사용자 중단(Ctrl+C): 지금까지의 결과를 저장해 --resume 으로 이어갈 수 있게 한다
            interrupted = True
            self.audit.event("interrupted", sweeps=sweeps_run)

        # ── PHASE 3.7: VULN (CVE/CWE 탐지 + 매핑) — 최종 출력까지 반영 ──
        self._run_vuln(report, host, target)

        # NSE 취약점 스크립트 보수적 제안(실행은 무겁고 길어 수동 제안으로)
        if host.open_ports:
            ports = ",".join(str(p) for p in host.open_ports)
            report.manual_suggestions.append(
                f"nmap -sV --script vuln -p {ports} {target}   # NSE 취약점 스캔(수동)")

        # ── CVE/CWE 레퍼런스 자동 수집(공식 출처, best-effort) ──
        if self.enricher is not None and not interrupted:   # 중단 시 네트워크 수집 생략
            all_cves = list(report.detected_cve)
            for m in report.vuln_matches:
                all_cves += m.cve
            if all_cves:
                try:
                    report.enriched = self.enricher.enrich(all_cves, report.detected_cwe)
                    if report.enriched:
                        self.audit.event("enriched",
                                         cves=[e.id for e in report.enriched])
                except Exception as e:   # noqa: BLE001 — 수집 실패는 진행 방해 금지
                    self.audit.event("enrich_error", error=str(e))

        # ── PHASE 3.9: 리버스쉘 자동 준비 (공격자 IP 확보 시) ──
        # 초기 침투에 바로 쓰도록 페이로드를 '자동 생성'해 리포트에 포함한다.
        # 생성만 — 실행(셸 획득)은 사용자가 권한 확인 대상에서 직접(안전 경계 유지).
        self._prepare_revshells(report)

        # ── PHASE 3.95: AWS/S3 열거 자동 준비 (호스트명/도메인 확보 시) ──
        # 버킷 후보·비인증 점검을 자동 생성. AWS 엔드포인트는 타겟 범위 밖이라
        # 실행하지 않고 준비만 한다(리버스쉘과 동일한 '생성 전용' 안전 경계).
        self._prepare_cloud(report)

        # ── PHASE 3.96: 권한상승 플레이북 자동 준비 (OS 식별 시) ──
        # OS 에 맞는 포스트-익스플로잇 권한상승 열거·점검 체크리스트를 자동 생성.
        # 대상 셸 안에서 실행하는 명령이라 에이전트는 준비만(생성 전용) 한다.
        self._prepare_privesc(report, prof)

        # ── PHASE 3.97: 해시 크래킹 자동 준비 (출력/볼트에서 해시 수집 시) ──
        # 캡처된 해시를 식별해 john/hashcat 명령을 자동 생성. 크래킹은 무겁고
        # 워드리스트가 필요해 에이전트는 준비만(생성 전용) 한다.
        self._prepare_crack(report)

        # ── PHASE 4: REPORT ──
        report.status = "interrupted" if interrupted else "done"
        if interrupted:
            report.message += "사용자 중단 — 진행 상태 저장(--resume 으로 이어서 진행). "
        elif self._goal_reached(report):
            report.goal_reached = True
            report.message += "목표 달성 — 남은 단계 조기 종료. "
        flag_state = f"user={'O' if report.user_flag else 'X'} root={'O' if report.root_flag else 'X'}"
        report.message += (f"OS={prof.os_class.value}({prof.tag}), "
                           f"스윕 {sweeps_run}회, "
                           f"진행단계 {'→'.join(phases_run) or '없음'}, "
                           f"KB enum {len(report.enum_findings)}건, "
                           f"LLM {len(report.llm_findings)}건, 플래그[{flag_state}]")
        self._persist(report, prior)
        self.audit.event("vuln", cve=report.detected_cve, cwe=report.detected_cwe,
                         matches=[m.name for m in report.vuln_matches])
        self.audit.event("session_end", status=report.status, message=report.message)
        return report

    def _restore(self, report: OrchestrationReport, prior: SessionState,
                 seen: set[str]) -> None:
        """재개: 이전 실행에서 '실제로 실행된' 명령과 결과·플래그·수동 제안을 복원한다.
        실행된 명령은 seen 에 넣어 다시 돌리지 않고(중복 공격·시간 낭비 방지), 복원한 결과는
        분석·명령 생성의 맥락이 되며 저장 시 이력이 사라지지 않는다. 실행되지 않은 명령
        (거부·미설치·미승인)은 복원하지 않아 이번 실행에서 다시 판단된다."""
        for src, dst in ((prior.enum_findings, report.enum_findings),
                         (prior.llm_findings, report.llm_findings)):
            for d in src or []:
                cmd = (d or {}).get("command", "")
                if not cmd or not d.get("ran") or cmd in seen:
                    continue
                seen.add(cmd)
                dst.append(EnumFinding(command=cmd, ran=True, note=d.get("note", ""),
                                       output=d.get("output", ""),
                                       phase=d.get("phase") or "enum"))
        for fd in prior.flags or []:
            value, kind = (fd or {}).get("value", ""), fd.get("kind", "")
            if not value or value in {f.value for f in report.flags}:
                continue
            report.flags.append(FlagHit(value, kind, fd.get("source", "")))
            report.flag_provenance.append(
                _prov.classify(kind, value, fd.get("source", "")))
            if self.world is not None:
                self.world.add_flag(kind, value)
        for m in prior.manual_suggestions or []:
            if m not in report.manual_suggestions:
                report.manual_suggestions.append(m)
        if report.enum_findings or report.llm_findings or report.flags:
            self.audit.event("resumed", findings=len(report.enum_findings)
                             + len(report.llm_findings), flags=len(report.flags))

    @staticmethod
    def _spent(findings: list[EnumFinding], base: int = 0) -> int:
        """이번 실행에서 예산을 쓴 시도 수 — 도구 미설치로 건너뛴 명령은 제외."""
        return sum(1 for f in findings[base:] if not f.skipped)

    def _tool_ok(self, cmd: str) -> bool:
        binary = binary_of(cmd)
        return not binary or self.is_tool_available(binary)

    def _goal_reached(self, report: OrchestrationReport) -> bool:
        """목표 달성 여부 — 달성하면 남은 공격 단계를 돌리지 않는다(불필요한 대상 상호작용·
        예산 낭비 방지). 대상 상호작용 출력에서 나온(provenance=exploit-derived) 플래그만
        인정해, 로컬 명령 출력의 미끼/예시 문자열로 조기 종료하지 않는다.
          · single(Jeopardy): 플래그 1개(접두 지정 시 그 접두)
          · boot2root(HTB) : user + root 둘 다"""
        trusted = {(p.kind, p.value) for p in report.flag_provenance
                   if p.verdict == "exploit-derived"}
        hits = [f for f in report.flags if (f.kind, f.value) in trusted]
        if self.flag_kind == "single":
            pref = tuple(p.lower() for p in self.flag_prefixes)
            return any(not pref or f.value.split("{", 1)[0].lower() in pref for f in hits)
        kinds = {f.kind for f in hits}
        return "user" in kinds and "root" in kinds

    def _refresh_analysis(self, report: OrchestrationReport, prof: ProfileResult,
                          host: NmapHost, target: str) -> None:
        """마지막 분석 이후 상태(관측·크리덴셜·취약점·권한)가 자랐을 때만 분석가를 다시
        부른다 — 계획이 최신 근거를 따르되, 변화 없으면 LLM 호출을 아낀다."""
        fp = self._world_fingerprint(report)
        if fp == self._analysis_fp:
            return
        self._analysis_fp = fp
        self._run_analyst(report, prof, host, target)

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
        fin = lambda f: {"command": f.command, "ran": f.ran, "note": f.note,
                         "output": f.output, "phase": f.phase}
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
        if self.vault is not None and self.vault.creds:
            st.credentials = self.vault.to_list()
        if report.flags:
            st.flags = [{"value": f.value, "kind": f.kind, "source": f.source}
                        for f in report.flags]
        st.add_history(report.message.strip() or report.status)
        self.state_store.save(st)

    def _enum_round(self, report: OrchestrationReport, host: NmapHost,
                    prof: ProfileResult, target: str,
                    seen: set[str], budget: int, phase: str = "enum") -> int:
        """해당 단계(phase)의 KB 제안 한 라운드. 새로 시도한 명령 수 반환."""
        if budget <= 0:
            return 0
        services = [p.service for p in host.ports if p.state == "open" and p.service]
        recs = self.kb.query(prof.os_class.value, host.open_ports, services, phase=phase)
        # 실행 후보(base, vcmd) 수집 — seen·budget·수동제안 처리는 여기서(결정적)
        to_run: list[tuple[str, str]] = []
        slots = 0   # 예산을 쓰는 후보 수(미설치 도구는 기록만 하고 예산 미사용)
        for rec in recs:
            for tmpl in rec.suggestions:
                for cmd, runnable in self._expand(tmpl, target):
                    if not runnable:
                        if cmd in seen:
                            continue
                        seen.add(cmd)
                        report.manual_suggestions.append(
                            cmd + f"   # [{_PHASE_LABEL.get(phase, phase)}] {rec.rule_name}")
                        continue
                    # 실행 가능한 명령은 옵션 조합(경우의 수) 변형까지 시도.
                    # variant_stats 가 있으면 학습된 성공률로 변형 순서를 재정렬한다.
                    for vcmd in expand_variants(cmd, self.max_variants, self.variant_stats):
                        if vcmd in seen:
                            continue
                        seen.add(vcmd)
                        if slots >= budget:
                            report.manual_suggestions.append(vcmd + "   # (상한 초과 — 수동)")
                            continue
                        to_run.append((cmd, vcmd))
                        if self._tool_ok(vcmd):
                            slots += 1
        if not to_run:
            return 0
        base_by_cmd = {vcmd: base for base, vcmd in to_run}
        if self.max_parallel <= 1:
            # 순차(기본): 게이트→실행→처리→변형학습 기록
            for base_cmd, vcmd in to_run:
                if self._goal_reached(report):   # 목표 달성 — 남은 후보는 실행하지 않음
                    break
                before = len(report.enum_findings)
                self._attempt(report, report.enum_findings, vcmd, phase)
                if len(report.enum_findings) > before:
                    self._record_variant_outcome(base_cmd, report.enum_findings[-1])
        else:
            # 병렬: 게이트(순차)→runner.run(동시)→처리(순차) 후 변형학습 기록
            gated = self._attempt_batch(report, report.enum_findings,
                                        [v for _, v in to_run], phase)
            for f in gated:
                self._record_variant_outcome(base_by_cmd.get(f.command, f.command), f)
        return len(to_run)

    def _record_variant_outcome(self, base_cmd: str, finding: EnumFinding) -> None:
        """실행된 변형의 결과(성공/실패)를 학습 통계에 기록. base 명령(fragment 없음)은
        학습 대상 아님. 성공 = 실행됐고 쓸만한 출력이 있음(요약 비어있지 않음)."""
        if self.variant_stats is None or finding is None:
            return
        frag = fragment_of(base_cmd, finding.command)
        if not frag:
            return
        success = bool(finding.ran and finding.output)
        self.variant_stats.record(binary_of(finding.command, strip_path=True), frag, success)

    def _harvest_creds(self, stdout: str, cmd: str, finding: EnumFinding) -> None:
        """출력에서 고신뢰 평문 자격을 수확한다. 월드엔 모두 반영(권한레벨 상승 →
        A1 재진입 활성화), 실행 볼트엔 셸-안전한 값만 추가(인젝션 차단). 중복은 무시."""
        pairs = harvest_creds(stdout)
        if not pairs:
            return
        from .creds import Credential
        for user, pw in pairs:
            if self.world is not None:
                self.world.add_cred(f"{user}:{pw}")
            self.audit.event("cred_harvested", cmd=cmd, user=user)
            note = f"🔑 크리덴셜 발견: {user}"
            finding.note = (finding.note + " " if finding.note else "") + note
            # 실행 볼트 추가는 셸-안전한 값만(신뢰불가 출처 → 명령 인젝션 방지)
            if (self.vault is not None and is_safe_for_cmd(user)
                    and is_safe_for_cmd(pw)):
                self.vault.add(Credential(username=user, password=pw,
                                          source="harvested"))

    def _expand(self, tmpl: str, target: str) -> list[tuple[str, bool]]:
        """볼트가 있으면 자격증명으로 플레이스홀더를 채워 확장, 없으면 {t}만 치환."""
        if self.vault is not None:
            return self.vault.expand(tmpl, target)
        cmd, auto = self.kb.format_suggestion(tmpl, target)
        return [(cmd, auto)]

    def _prereq_met(self, phase: str) -> tuple[bool, str]:
        """A2: 단계 전제조건 판정. 월드 모델의 권한레벨·크리덴셜로 결정한다.
        enum/access 는 항상 가능. privesc/lateral 은 발판(쉘)·크리덴셜이 있어야
        투기적 LLM 제안이 의미있다(없으면 KB 수동 가이드만 남긴다)."""
        w = self.world
        if w is None or phase in ("enum", "access"):
            return True, ""
        has_foothold = w.has_access("user")
        has_cred = bool(w.creds)
        has_secret = bool(w.loot) or has_cred   # 해시/자격 등 측면이동 수단
        if phase == "privesc":
            if has_foothold or has_cred:
                return True, ""
            return False, "전제 미충족: user 쉘 또는 크리덴셜 필요"
        if phase == "lateral":
            if has_foothold or has_secret:
                return True, ""
            return False, "전제 미충족: 크리덴셜/해시 등 이동수단 필요"
        return True, ""

    def _note_terms(self, host: NmapHost, prof: ProfileResult,
                    phase: str, report: OrchestrationReport) -> list[str]:
        """B5: 노트 관련도 랭킹용 쿼리 용어 — 서비스·OS·단계·탐지 취약점에서 수집."""
        terms: list[str] = []
        if host is not None:
            for p in host.ports:
                if p.state == "open" and p.service:
                    terms.append(p.service)
                    prod = getattr(p, "product", "") or ""
                    if prod:
                        terms.append(prod.split()[0])
        if prof is not None:
            terms.append(prof.os_class.value)
        terms.append(_PHASE_LABEL.get(phase, phase))
        terms.append(phase)
        terms += list(report.detected_cve)
        return terms

    def _acquire_knowledge(self, report: OrchestrationReport, host: NmapHost,
                           prof: ProfileResult) -> None:
        """자율 지식 획득 — 관측된 기술 용어 중 '모르는 것'을 감지해 권위 출처에서
        자동 학습(allowlist·P1 가드 내장)하고, 현재 KB 에 즉시 반영한다. 매핑 불가
        용어는 지어내지 않고 report.knowledge_gaps 에 기록(수동 조사 안내)."""
        if not self.learn_gaps:
            return
        from . import knowledge_gaps as kg
        terms = self._note_terms(host, prof, "enum", report)
        # 분석가가 지목한 기술 키워드도 공백 후보로(있으면) — 상태 성장 반영
        remaining = self.max_gap_learn - len(self._acquired_topics)
        if remaining <= 0:
            # 예산 소진 — 미해석 공백만 계속 기록(학습 생략)
            out = kg.acquire(terms, self.kb, None, self._acquired_topics, 0)
        else:
            out = kg.acquire(terms, self.kb, self.learner,
                             self._acquired_topics, max(0, remaining),
                             web_learner=self.web_learner)
        for line in out.acquired:
            if line not in report.acquired_knowledge:
                report.acquired_knowledge.append(line)
                self.audit.event("knowledge_acquired", detail=line)
                if self.world is not None:
                    self.world.add_loot(f"자율학습: {line}")
        for term in out.unresolved:
            if term not in report.knowledge_gaps:
                report.knowledge_gaps.append(term)
                self.audit.event("knowledge_gap", term=term)

    @staticmethod
    def _low_confidence(report: OrchestrationReport) -> bool:
        """B6: 분석가 산출의 '확신도' 가 낮으면(하/low) True. 적응형 tier 상향 근거."""
        text = (getattr(report, "analysis", "") or "")
        # '확신도: 하' 처럼 항목 값의 첫 등급만 본다(근거 문장 속 '하위'·'below' 오탐 방지).
        # 다관점 분석은 가설 줄에 '[우선:하]' 도 쓰므로 '확신도' 항목 줄만 대상으로 한다.
        for ln in text.splitlines():
            m = re.match(r"\s*(?:확신도|confidence)\s*[:：]\s*\(?\s*(상|중|하|high|medium|low)",
                         ln, re.I)
            if m:
                return m.group(1).lower() in ("하", "low")
        return False

    def _run_analyst(self, report: OrchestrationReport, prof: ProfileResult,
                     host: NmapHost, target: str) -> None:
        """B3 분석가 — 상태를 읽고 가설·공격경로·다음집중·확신도를 산출해
        report.analysis 에 저장(이후 명령 생성 컨텍스트로 주입). LLM 없으면 no-op."""
        if self.llm_router is None or not hasattr(self.llm_router, "analyze"):
            return
        prior = [f"{f.command} => {f.output}"
                 for f in (report.enum_findings + report.llm_findings) if f.output]
        context = {
            "platform": self.platform_name,
            "profile": prof.summary() if prof else "",
            "open_ports": [str(p) for p in host.ports if p.state == "open"],
            "state": self.world.context_lines() if self.world is not None else [],
            "findings": prior[-10:],
        }
        try:
            text = self.llm_router.analyze(context, target)
        except Exception as e:   # 분석 실패는 전체를 깨지 않는다
            self.audit.event("analyst_error", error=str(e))
            return
        if text:
            report.analysis = text
            self.audit.event("analyst", chars=len(text))

    def _llm_round(self, report: OrchestrationReport, host: NmapHost,
                   prof: ProfileResult, target: str,
                   seen: set[str], budget: int, phase: str = "enum") -> int:
        """해당 단계의 LLM 제안 한 라운드. 이전 관측을 컨텍스트에 반영(적응)."""
        if budget <= 0:
            return 0
        services = [p.service for p in host.ports if p.state == "open" and p.service]
        recs = self.kb.query(prof.os_class.value, host.open_ports, services, phase=phase)
        prior = [f"{f.command} => {f.output}"
                 for f in (report.enum_findings + report.llm_findings) if f.output]
        context = {
            "phase": _PHASE_LABEL.get(phase, phase),
            "profile": prof.summary(),
            # 구조화 상태(월드 모델) — 원시 로그 대신 정돈된 사실을 LLM 에 제공
            "state": self.world.context_lines() if self.world is not None else [],
            # B3 분석가의 판단 — 명령 생성을 유도(가설·경로·집중)
            "analysis": report.analysis,
            "open_ports": [str(p) for p in host.ports if p.state == "open"],
            # 명령 없는 가이드 규칙은 이름만 가면 쓸모가 없으므로 가이드(note) 앞부분을 전달
            "kb": [f"{r.rule_name}: " + (", ".join(r.suggestions)
                                          or (r.note[:160] + ("…" if len(r.note) > 160 else "")))
                   for r in recs[:5]],
            # B5(경량 RAG): 현재 서비스·OS·단계·취약점에 관련도 높은 노트만 주입
            "notes": self.kb.relevant_notes(
                self._note_terms(host, prof, phase, report), 3),
            "findings": prior[-10:],
            # 플랫폼 인식 — LLM 프롬프트가 HTB/Jeopardy·카테고리에 맞게 조립된다
            "platform": self.platform_name,
            "jeopardy": self.flag_kind == "single",
            "category": self.category,
            "flag_prefixes": ("/".join(f"{p}{{...}}" for p in self.flag_prefixes)
                              if self.flag_prefixes else ""),
        }
        try:
            from .llm.base import tier_for_phase, Tier
            base_tier = tier_for_phase(phase)
            # B6 적응형 tier: 분석 확신도 '하' 면 처음부터 강력 모델로 상향
            if self._low_confidence(report) and base_tier != Tier.STRONG:
                base_tier = Tier.STRONG
                self.audit.event("tier_escalate", reason="low_confidence", phase=phase)
            cmds = self.llm_router.suggest_commands(
                context, target, tier=base_tier, max_items=budget)
            # B6: 저단계 모델이 쓸만한 명령을 못 내면(빈 결과) 강력 모델로 1회 승격 재시도
            if not cmds and base_tier != Tier.STRONG:
                self.audit.event("tier_escalate", reason="empty_result", phase=phase)
                cmds = self.llm_router.suggest_commands(
                    context, target, tier=Tier.STRONG, max_items=budget)
        except Exception as e:  # LLM 백엔드 오류는 전체를 깨지 않는다
            report.manual_suggestions.append(f"(LLM 제안 실패: {e})")
            return 0
        meta = getattr(self.llm_router, "last_meta", {}) or {}
        attempted = 0
        for cmd in cmds:
            if cmd in seen:
                continue
            if attempted >= budget or self._goal_reached(report):
                break
            seen.add(cmd)
            self._attempt(report, report.llm_findings, cmd, phase)
            # B4: 구조화 출력의 가설·근거를 finding 비고에 덧붙임(어느 가설을 검증했는지 추적)
            m = meta.get(cmd) or {}
            tags = [t for t in (("가설 " + m["hypothesis"]) if m.get("hypothesis") else "",
                                ("근거: " + m["rationale"]) if m.get("rationale") else "") if t]
            if tags and report.llm_findings:
                f = report.llm_findings[-1]
                f.note = (f.note + " · " if f.note else "") + " · ".join(tags)
            if self._tool_ok(cmd):
                attempted += 1
        return attempted

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
        # 월드 모델에 확인 취약점 반영(단일 상태원)
        if self.world is not None:
            for cve in report.detected_cve + report.detected_cwe:
                self.world.add_vuln(cve)
            for m in report.vuln_matches:
                ids = " ".join(m.cve + m.cwe)
                self.world.add_vuln(f"{m.name}" + (f" ({ids})" if ids else ""))

    def _prepare_revshells(self, report: OrchestrationReport) -> None:
        """공격자 IP(VPN tun0 등)가 확보되면 리버스쉘 페이로드를 자동 생성해
        리포트에 담는다. 생성 전용 — 실행은 하지 않는다(안전 경계 유지).
        공격자 IP 가 없으면(미탐지) 조용히 생략한다."""
        attacker_ips = list(self.guard.attacker_ips or [])
        if not attacker_ips:
            return
        lhost = str(attacker_ips[0])
        lport = self.revshell_port
        try:
            from . import revshell
            report.revshells = revshell.generate(lhost, lport)
            report.revshell_lhost = lhost
            report.revshell_lport = lport
            self.audit.event("revshell_prepared", lhost=lhost, lport=lport,
                             count=len(report.revshells))
        except Exception as e:   # noqa: BLE001 — 생성 실패가 전체를 깨지 않도록
            self.audit.event("revshell_error", error=str(e))

    def _prepare_cloud(self, report: OrchestrationReport) -> None:
        """호스트명/도메인이 확보되면 AWS/S3 열거(버킷 후보+점검)를 자동 준비한다.
        생성 전용 — AWS 엔드포인트는 타겟 범위 밖이라 실행하지 않는다. 버킷명 후보를
        만들 이름(호스트명/도메인)이 없으면(IP 뿐) 조용히 생략한다."""
        names: list[str] = []
        if self.hosts_map:
            names.extend(self.hosts_map.values())
            names.extend(self.hosts_map.keys())
        if self.guard.bound_host:
            names.append(str(self.guard.bound_host))
        names.append(report.target)
        try:
            from . import cloud
            prep = cloud.generate(names)
            if not prep.candidates:
                return
            report.cloud_candidates = prep.candidates
            report.cloud_checks = prep.checks
            self.audit.event("cloud_prepared", keyword=prep.keyword,
                             candidates=len(prep.candidates),
                             checks=len(prep.checks))
        except Exception as e:   # noqa: BLE001 — 준비 실패가 전체를 깨지 않도록
            self.audit.event("cloud_error", error=str(e))

    def _prepare_privesc(self, report: OrchestrationReport, prof: ProfileResult) -> None:
        """OS 식별 결과로 권한상승 플레이북을 자동 준비한다. 생성 전용 — 획득한
        대상 셸에서 사용자가 직접 실행한다(에이전트는 셸 없음). OS 미상이면 생략."""
        os_class = prof.os_class.value if prof else "unknown"
        if os_class not in ("linux", "windows", "windows_ad"):
            return
        attacker_ip = ""
        if self.guard.attacker_ips:
            attacker_ip = str(list(self.guard.attacker_ips)[0])
        # 탐지 CVE(출력 추출) + 버전매칭 CVE 를 합쳐 LPE 후보 승격에 반영
        cve_pool = list(report.detected_cve)
        for m in report.vuln_matches:
            cve_pool.extend(m.cve)
        try:
            from . import privesc
            plan = privesc.build(os_class, attacker_ip, cve_pool)
            report.privesc_steps = plan.steps
            report.privesc_cve_candidates = plan.cve_candidates
            self.audit.event("privesc_prepared", os=os_class,
                             steps=len(plan.steps),
                             cve_candidates=len(plan.cve_candidates))
        except Exception as e:   # noqa: BLE001 — 준비 실패가 전체를 깨지 않도록
            self.audit.event("privesc_error", error=str(e))

    def _world_fingerprint(self, report: OrchestrationReport) -> tuple:
        """스윕 간 '상태 성장' 판정용 지문. 관측·크리덴셜·서비스·권한이 늘면 달라진다.
        스윕 후 지문이 그대로면 더 진전이 없다는 뜻이라 반복을 조기 종료한다(유한)."""
        w = self.world
        return (
            len(report.enum_findings),
            len(report.llm_findings),
            len(w.creds) if w else 0,
            len(w.services) if w else 0,
            len(w.loot) if w else 0,
            len(w.proven_vulns) if w else 0,
            w.access_level if w else "none",
        )

    def _prepare_crack(self, report: OrchestrationReport) -> None:
        """enum/LLM 출력·크리덴셜 볼트에서 해시를 수집해 크래킹 명령을 자동 준비한다.
        생성 전용 — 크래킹은 사용자 환경에서 실행. 해시가 없으면 조용히 생략."""
        # 실행 원시출력에서 수집한 해시(요약 전 — _attempt 에서 스캔) + 요약출력 보강
        hashes: list[str] = list(getattr(self, "_found_hashes", []))
        for f in report.enum_findings + report.llm_findings:
            if f.output:
                hashes.extend(crack_scan(f.output))
        for p in report.host.ports if report.host else []:
            for sc in p.scripts.values():
                hashes.extend(crack_scan(sc))
        # 크리덴셜 볼트의 NT 해시(PtH)도 크래킹 후보
        if self.vault is not None:
            for c in self.vault.creds:
                nt = getattr(c, "nt_hash", None)
                if nt:
                    # PtH NT 해시는 'LM:NT' 형식일 수 있어 NT 부분만 사용
                    hashes.append(nt.split(":")[-1])
        if not hashes:
            return
        try:
            from . import crack
            report.crack_jobs = crack.prepare(hashes)
            if report.crack_jobs:
                self.audit.event("crack_prepared", jobs=len(report.crack_jobs))
        except Exception as e:   # noqa: BLE001 — 준비 실패가 전체를 깨지 않도록
            self.audit.event("crack_error", error=str(e))

    def _gate(self, report: OrchestrationReport, findings: list[EnumFinding],
              cmd: str, phase: str) -> EnumFinding | None:
        """3관문(도구·검증·범위·승인)을 순차 수행(공유상태 변경은 단일 스레드).
        통과하면 '실행 대상' finding 반환, 아니면 사유를 기록하고 None."""
        finding = EnumFinding(command=cmd, phase=phase)
        findings.append(finding)
        self.audit.event("proposed", cmd=cmd, phase=phase)
        gs = report.gate_stats
        gs["proposed"] += 1

        binary = binary_of(cmd)
        if binary and not self.is_tool_available(binary):
            finding.note = f"건너뜀: '{binary}' 미설치"
            finding.skipped = True
            gs["tool_missing"] += 1
            self.audit.event("skipped", cmd=cmd, reason="tool-missing", binary=binary)
            return None
        vrep: ValidationReport = validate(cmd)
        if not vrep.ok:
            finding.note = "검증 실패: " + "; ".join(str(i) for i in vrep.errors)
            gs["rejected_validate"] += 1
            self.audit.event("rejected", cmd=cmd, stage="validate",
                             errors=[str(i) for i in vrep.errors])
            return None
        try:
            sres: CommandScopeResult = self.guard.inspect_command(cmd, hosts_map=self.hosts_map)
        except ScopeViolation as e:
            finding.note = f"범위 오류: {e}"
            gs["rejected_scope"] += 1
            self.audit.event("rejected", cmd=cmd, stage="scope", reason=str(e))
            return None
        if not self.approver(cmd, vrep, sres):
            review = [i.message for i in vrep.review]
            if review:
                # 동적·원격 코드 실행: 자동실행 대신 수동 제안으로 강등(사람이 내용 확인)
                finding.note = "미승인(실행위험): " + "; ".join(review)
                gs["denied_review"] += 1
                entry = cmd + "   # (실행위험 — 내용 확인 후 수동)"
                if entry not in report.manual_suggestions:
                    report.manual_suggestions.append(entry)
            else:
                finding.note = "미승인(범위밖/사용자 거부)"
                gs["denied_scope"] += 1
            self.audit.event("denied", cmd=cmd, in_scope=sres.auto_allowed, review=review)
            return None
        return finding

    def _process(self, report: OrchestrationReport, finding: EnumFinding, out) -> None:
        """실행 결과를 반영(파싱·플래그/해시/크리덴셜 스캔). 공유상태를 변경하므로
        반드시 단일 스레드에서, 제출 순서대로 호출한다(병렬 실행과 분리)."""
        cmd = finding.command
        finding.ran = out.launched
        report.gate_stats["executed" if out.launched else "run_failed"] += 1
        if not out.launched:
            finding.note = f"실행 실패: {out.error}"
            self.audit.event("executed", cmd=cmd, launched=False, error=out.error)
            self._diagnose(report, finding, out)   # 실행 실패도 원인 분류(환경 문제)
            return
        finding.output = summarize_tool_output(cmd, out.stdout, out.stderr)
        self.audit.event("executed", cmd=cmd, launched=True,
                         returncode=out.returncode, summary=finding.output)
        # 실패 진단(사람 확인용) — 404/403/타임아웃 등 원인 분류. 자동 재공격 아님.
        self._diagnose(report, finding, out)
        # 플래그 스캔 — 출력에서 플래그 획득(플랫폼별 종류/접두 적용)
        for hit in scan_flags(cmd, out.stdout, flag_kind=self.flag_kind,
                              prefixes=self.flag_prefixes):
            if hit.value not in {f.value for f in report.flags}:
                report.flags.append(hit)
                # 출처 검증(실행 트레이스 기반) — 이 플래그를 만든 명령을 분류해 기록.
                prov = _prov.classify(hit.kind, hit.value, cmd, finding.phase)
                report.flag_provenance.append(prov)
                note_mark = f"🚩 {hit.kind} flag"
                if prov.verdict != "exploit-derived":
                    note_mark += f"({prov.label})"
                finding.note = (finding.note + " " if finding.note else "") + note_mark
                self.audit.event("flag_found", kind=hit.kind, value=hit.value, cmd=cmd,
                                 provenance=prov.verdict)
                if self.world is not None:
                    self.world.add_flag(hit.kind, hit.value)
        # 해시 스캔 — 원시출력(요약 전)에서 크래킹 대상 해시 수집(크래킹 자동 준비용)
        for hv in crack_scan(out.stdout):
            if hv not in self._found_hashes:
                self._found_hashes.append(hv)
                self.audit.event("hash_found", cmd=cmd, hash=hv[:24])
                if self.world is not None:
                    self.world.add_loot(f"해시: {hv[:40]}{'…' if len(hv) > 40 else ''}")
        # 크리덴셜 자동 수확 — 원시출력에서 고신뢰 평문 자격 추출. 월드엔 모두 반영,
        # 실행 볼트엔 셸-안전한 값만(신뢰불가 출처 인젝션 차단). A1 재진입을 활성화.
        self._harvest_creds(out.stdout, cmd, finding)

    def _diagnose(self, report: OrchestrationReport, finding: EnumFinding, out) -> None:
        """실패를 원인별로 분류해 finding 비고에 덧붙이고 report.blockers 에 기록한다.
        '대상 응답'(404/403…)과 '환경/도구/네트워크 문제'를 구분해 사람이 판단하게 한다.
        자동 재시도·경로 변경은 하지 않는다(판단 재료만 제공)."""
        try:
            diag = diagnostics.diagnose(finding.command, out)
        except Exception as e:   # noqa: BLE001 — 진단 실패가 본 작업을 막지 않음
            self.audit.event("diagnose_error", cmd=finding.command, error=str(e))
            return
        if diag is None:
            return
        tag = f"[{diag.kind}] {diag.label}"
        finding.note = (finding.note + " · " if finding.note else "") + tag
        report.blockers.append((finding.command, diag))
        self.audit.event("diagnosis", cmd=finding.command, category=diag.category,
                         is_target=diag.is_target)

    def _safe_run(self, cmd: str) -> "RunOutput":
        """runner.run 을 예외로부터 보호. 어떤 러너 예외도 실패 RunOutput 으로 흡수해
        한 명령의 실패가 라운드/배치 전체를 깨지 않도록 한다(병렬 map 보호 포함)."""
        try:
            return self.runner.run(cmd, timeout=180)
        except Exception as e:   # noqa: BLE001
            self.audit.event("run_exception", cmd=cmd, error=f"{type(e).__name__}: {e}")
            return RunOutput(cmd, error=f"러너 예외: {type(e).__name__}: {e}", returncode=-1)

    def _attempt(self, report: OrchestrationReport, findings: list[EnumFinding],
                 cmd: str, phase: str = "enum") -> None:
        """순차 실행: 게이트 → (통과 시) 실행 → 결과 처리."""
        finding = self._gate(report, findings, cmd, phase)
        if finding is None:
            return
        out = self._safe_run(finding.command)
        self._process(report, finding, out)

    def _attempt_batch(self, report: OrchestrationReport, findings: list[EnumFinding],
                       cmds: list[str], phase: str) -> list[EnumFinding]:
        """병렬 실행: 게이트를 '순차로' 통과시킨 뒤, 통과한 명령의 runner.run 만
        스레드풀로 동시 실행하고, 결과 처리는 다시 '제출 순서대로 단일 스레드'로
        수행한다 → 공유상태 경쟁 없음·결정적 순서 보존. 게이트 통과 finding 목록 반환."""
        gated: list[EnumFinding] = []
        for cmd in cmds:
            f = self._gate(report, findings, cmd, phase)
            if f is not None:
                gated.append(f)
        if not gated:
            return []
        from concurrent.futures import ThreadPoolExecutor
        workers = max(1, min(self.max_parallel, len(gated)))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            # map 은 입력 순서대로 결과를 돌려주므로 결정성 유지(I/O 만 병렬).
            # _safe_run 이 각 작업 예외를 흡수 → 한 명령 실패가 배치 전체를 깨지 않음.
            outs = list(ex.map(lambda f: self._safe_run(f.command), gated))
        for f, out in zip(gated, outs):
            self._process(report, f, out)
        return gated
