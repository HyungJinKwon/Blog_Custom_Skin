"""
Bench — 로컬 모의 문제로 '풀이 성공률·명령 수·시간·비용' 측정(오프라인)
=====================================================================

해커톤 발표·개선 효과 검증용. `bench/challenges/*.json` 의 모의 문제는 실제 네트워크·도구 없이
가짜 응답만 돌려주는 연습 대상이다(교육용 데이터). 같은 문제를 N번 시도해 성공률과 pass@k 를
집계하고, 시도마다 감사 로그(JSONL)를 남겨 `--replay` 로 단계별 재생할 수 있게 한다.

문제 파일 형식:
  {"name", "title", "difficulty"(easy|medium|hard), "lesson",
   "ports": [[포트, "서비스"], ...],
   "responses": [{"match": "<명령에 포함된 문자열>", "stdout": "..."}, ...],   # 위에서부터 먼저 맞는 것
   "flag": "FLAG{...}"}
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

BENCH_TARGET = "10.129.1.5"          # 모의 대상 주소(실제 통신 없음 — 가짜 러너가 응답)
_DIFF_ORDER = {"easy": 0, "medium": 1, "hard": 2}


@dataclass
class Challenge:
    name: str
    title: str
    flag: str
    ports: list = field(default_factory=list)
    responses: list = field(default_factory=list)
    difficulty: str = "medium"
    lesson: str = ""


@dataclass
class AttemptResult:
    challenge: str
    attempt: int
    solved: bool
    executed: int
    proposed: int
    elapsed_sec: float
    steps_to_flag: int = 0          # 몇 번째 실행 명령에서 플래그가 나왔나(0=못 찾음)
    verified: bool = False          # 대상 상호작용 출력에서 나온 플래그로 풀림(provenance=exploit-derived)
    approvals_needed: int = 0       # 사람 확인이 필요했던 횟수(승인 부담 — 적을수록 초보자 친화)
    llm_calls: int = 0
    cost: float = 0.0
    trace: str = ""


@dataclass
class ChallengeStats:
    name: str
    title: str
    difficulty: str
    attempts: int
    solved: int
    verified: int
    rate: float
    pass_at_k: bool
    avg_executed: float
    avg_steps_to_flag: float
    avg_elapsed_sec: float
    cost: float
    avg_llm_calls: float = 0.0      # 시도당 LLM 호출 수(방향성 지표 — 적을수록 헛돌지 않음)


class BenchError(ValueError):
    pass


def default_suite_dir() -> str:
    """번들 문제 세트 위치(작업 디렉터리 → 저장소 기준 순으로 찾음)."""
    here = Path("bench/challenges")
    if here.is_dir():
        return str(here)
    return str(Path(__file__).resolve().parents[2] / "bench" / "challenges")


def load_suite(path: str) -> list[Challenge]:
    p = Path(path)
    files = sorted(p.glob("*.json")) if p.is_dir() else [p]
    if not files or not all(f.is_file() for f in files):
        raise BenchError(f"문제 파일을 찾을 수 없음: {path}")
    out: list[Challenge] = []
    for f in files:
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise BenchError(f"{f.name}: 읽기 실패 — {e}") from e
        missing = [k for k in ("name", "title", "flag", "ports") if not d.get(k)]
        if missing:
            raise BenchError(f"{f.name}: 필수 키 없음 — {', '.join(missing)}")
        out.append(Challenge(
            name=str(d["name"]), title=str(d["title"]), flag=str(d["flag"]),
            ports=[(int(n), str(s)) for n, s in d["ports"]],
            responses=list(d.get("responses") or []),
            difficulty=str(d.get("difficulty") or "medium"), lesson=str(d.get("lesson") or "")))
    out.sort(key=lambda c: (_DIFF_ORDER.get(c.difficulty, 9), c.name))
    return out


def _nmap_xml(ports) -> str:
    rows = "".join(f'<port protocol="tcp" portid="{n}"><state state="open"/>'
                   f'<service name="{s}"/></port>' for n, s in ports)
    return (f'<?xml version="1.0"?><nmaprun><host><status state="up"/>'
            f'<address addr="{BENCH_TARGET}"/><ports>{rows}</ports></host></nmaprun>')


def responder(ch: Challenge) -> Callable[[str], str]:
    """모의 대상: 포트스캔엔 XML, 그 외엔 첫 번째로 맞는 응답(없으면 빈 출력)."""
    xml = _nmap_xml(ch.ports)

    def respond(cmd: str) -> str:
        if cmd.startswith("nmap") and "-oX -" in cmd:
            return xml
        low = cmd.lower()
        for r in ch.responses:
            if str(r.get("match", "")).lower() in low:
                return str(r.get("stdout", ""))
        return ""
    return respond


def run_attempt(ch: Challenge, n: int, kb, router=None, trace_path: str = "",
                **orch_kw) -> AttemptResult:
    from .audit import AuditLog, NullAudit
    from .orchestrator import Orchestrator
    from .scope_guard import ScopeGuard
    from .tools.recon import auto_approve_in_scope
    from .tools.runner import FakeRunner

    guard = ScopeGuard.from_cidr_strings()
    guard.bind_target(BENCH_TARGET)
    audit = AuditLog(trace_path) if trace_path else NullAudit()
    calls0 = getattr(router, "calls", 0) if router else 0
    cost0 = float(getattr(router, "total_cost", 0.0) or 0.0) if router else 0.0
    orc = Orchestrator(guard, FakeRunner(responder(ch)), kb, auto_approve_in_scope,
                       llm_router=router, flag_kind="single", flag_prefixes=("FLAG",),
                       platform_name="Bench", is_tool_available=lambda b: True, quiet=True,
                       audit=audit, **orch_kw)
    t0 = time.monotonic()
    try:
        rep = orc.run()
    finally:
        audit.close()
    elapsed = time.monotonic() - t0
    solved = any(f.value == ch.flag for f in rep.flags)
    verified = any(p.value == ch.flag and p.verdict == "exploit-derived"
                   for p in getattr(rep, "flag_provenance", []))
    gs = rep.gate_stats
    approvals = int(gs.get("denied_review", 0)) + int(gs.get("denied_scope", 0))
    steps = 0
    if solved:
        ran = [f for f in rep.enum_findings + rep.llm_findings if f.ran]
        for i, f in enumerate(ran, 1):
            if ch.flag in (f.output or "") or "🚩" in (f.note or ""):
                steps = i
                break
    return AttemptResult(
        challenge=ch.name, attempt=n, solved=solved,
        executed=int(rep.gate_stats.get("executed", 0)),
        proposed=int(rep.gate_stats.get("proposed", 0)),
        elapsed_sec=round(elapsed, 3), steps_to_flag=steps,
        verified=verified, approvals_needed=approvals,
        llm_calls=(getattr(router, "calls", 0) - calls0) if router else 0,
        cost=round((float(getattr(router, "total_cost", 0.0) or 0.0) - cost0) if router else 0.0, 6),
        trace=trace_path)


def run_bench(challenges: list[Challenge], attempts: int = 1, kb=None, router=None,
              trace_dir: str = "", progress: Callable[[str], None] | None = None,
              **orch_kw) -> list[AttemptResult]:
    """모든 문제를 attempts 번씩 시도. 시도마다 감사 로그를 trace_dir 에 남긴다(지정 시)."""
    if kb is None:
        from .knowledge import KnowledgeBase
        kb = KnowledgeBase.load()
    attempts = max(1, int(attempts))
    results: list[AttemptResult] = []
    if trace_dir:
        os.makedirs(trace_dir, exist_ok=True)
    for ch in challenges:
        for n in range(1, attempts + 1):
            trace = os.path.join(trace_dir, f"{ch.name}_{n}.jsonl") if trace_dir else ""
            r = run_attempt(ch, n, kb, router=router, trace_path=trace, **orch_kw)
            results.append(r)
            if progress:
                progress(f"{ch.name} #{n}: {'성공' if r.solved else '실패'} "
                         f"(명령 {r.executed}개, {r.elapsed_sec:.2f}초)")
    return results


def summarize(challenges: list[Challenge], results: list[AttemptResult]) -> list[ChallengeStats]:
    out: list[ChallengeStats] = []
    for ch in challenges:
        rs = [r for r in results if r.challenge == ch.name]
        if not rs:
            continue
        ok = [r for r in rs if r.solved]
        vok = [r for r in rs if r.verified]
        out.append(ChallengeStats(
            name=ch.name, title=ch.title, difficulty=ch.difficulty, attempts=len(rs),
            solved=len(ok), verified=len(vok), rate=round(len(ok) / len(rs), 3),
            pass_at_k=bool(ok),
            avg_executed=round(sum(r.executed for r in rs) / len(rs), 1),
            avg_steps_to_flag=round(sum(r.steps_to_flag for r in ok) / len(ok), 1) if ok else 0.0,
            avg_elapsed_sec=round(sum(r.elapsed_sec for r in rs) / len(rs), 3),
            cost=round(sum(r.cost for r in rs), 6),
            avg_llm_calls=round(sum(r.llm_calls for r in rs) / len(rs), 1)))
    return out


def totals(stats: list[ChallengeStats]) -> dict:
    n = len(stats)
    att = sum(s.attempts for s in stats)
    by_diff: dict[str, list[int]] = {}
    for s in stats:
        d = by_diff.setdefault(s.difficulty, [0, 0])
        d[0] += int(s.pass_at_k)
        d[1] += 1
    tot_solved = sum(s.solved for s in stats)
    return {
        "challenges": n,
        "solved_any": sum(s.pass_at_k for s in stats),          # pass@k: k번 중 한 번이라도
        "verified_any": sum(bool(s.verified) for s in stats),   # 검증된 풀이(대상 상호작용 유래)
        "attempt_success_rate": round(tot_solved / att, 3) if att else 0.0,
        # 검증된 풀이율: 성공 중 '대상과 실제 상호작용한 출력에서 나온 플래그'의 비율(ctf-abacus)
        "verified_solve_rate": round(sum(s.verified for s in stats) / tot_solved, 3) if tot_solved else 0.0,
        "by_difficulty": {k: {"solved": v[0], "total": v[1]} for k, v in by_diff.items()},
        "total_cost": round(sum(s.cost for s in stats), 6),
        # 풀린 문제 1건당 LLM 호출 수 — 방향을 잡고 진행할수록 작아진다(LLM 미사용이면 0)
        "llm_calls": round(sum(s.avg_llm_calls * s.attempts for s in stats)),
        "llm_calls_per_solve": (round(sum(s.avg_llm_calls * s.attempts for s in stats) / tot_solved, 1)
                                if tot_solved else 0.0),
    }


def to_dict(suite: str, attempts: int, llm: str, stats: list[ChallengeStats],
            results: list[AttemptResult]) -> dict:
    return {"suite": suite, "attempts": attempts, "llm": llm, "totals": totals(stats),
            "challenges": [asdict(s) for s in stats], "results": [asdict(r) for r in results]}


def render(stats: list[ChallengeStats], attempts: int, llm: str) -> str:
    from . import ui
    t = totals(stats)
    def cell(text, width: int, right: bool = False) -> str:   # 한글 표시 폭 기준 정렬
        pad = " " * max(0, width - ui.display_width(str(text)))
        return pad + str(text) if right else str(text) + pad
    cols = [("문제", 18, False), ("난이도", 7, False), ("성공", 6, True), ("성공률", 7, True),
            ("평균 명령", 10, True), ("플래그까지", 11, True), ("평균 시간", 10, True)]
    lines = [ui.heading(f"BENCH  (시도 {attempts}회 · LLM {llm})", "🏁")]
    lines.append(ui.dim("    " + " ".join(cell(h, w, r) for h, w, r in cols)))
    for s in stats:
        mark = ui.ok("✔") if s.pass_at_k else ui.warn("✗")
        vals = [s.name, s.difficulty, f"{s.solved}/{s.attempts}", f"{s.rate:.0%}",
                s.avg_executed, f"{s.avg_steps_to_flag}번째" if s.pass_at_k else "-",
                f"{s.avg_elapsed_sec:.2f}s"]
        lines.append(f"  {mark} " + " ".join(cell(v, w, r) for v, (_, w, r) in zip(vals, cols)))
    diff = " · ".join(f"{k} {v['solved']}/{v['total']}" for k, v in
                      sorted(t["by_difficulty"].items(), key=lambda kv: _DIFF_ORDER.get(kv[0], 9)))
    lines.append("")
    lines.append(ui.kv("풀린 문제", f"{t['solved_any']}/{t['challenges']} (pass@{attempts})  ·  {diff}", 10))
    lines.append(ui.kv("시도 성공률", f"{t['attempt_success_rate']:.0%}", 10))
    lines.append(ui.kv("검증된 풀이율", f"{t['verified_solve_rate']:.0%} "
                       "(성공 중 대상 상호작용 출력에서 나온 플래그 비율)", 10))
    if t["llm_calls"]:
        lines.append(ui.kv("LLM 호출", f"총 {t['llm_calls']}회 · 풀이 1건당 {t['llm_calls_per_solve']}회 "
                           "(적을수록 방향을 잡고 진행)", 10))
    if t["total_cost"]:
        lines.append(ui.kv("LLM 비용", f"${t['total_cost']:.4f}", 10))
    return "\n".join(lines)
