"""
Promote — 로컬 학습 노트를 검토 가능한 '번들 시드' 보강으로 승격
====================================================================

문제: 번들 시드(seed-<주제>.md)는 저장소에 커밋되어 모든 사용자가 동일하게
시작한다(완성형 베이스라인). 반면 `--learn`·자율 지식 획득이 만드는 learned-*.md 는
환경마다 달라 .gitignore 된다 — 그래서 '성장'이 각자 따로 일어나 성능이 갈린다.

해결(검토 후 승격): 각자 학습한 노트 중 **품질 관문을 통과한 항목만** 시드의
`## 최신 보강(승격)` 섹션으로 옮긴다. 사용자가 그 diff 를 커밋·PR 하면, 리뷰·CI 를
거쳐 병합되는 순간 모든 사용자의 베이스라인이 함께 자란다.

원칙
  - 사람이 다듬은 시드 본문(개요·핵심 기법·표준 도구·블루팀 탐지·완화)은 건드리지
    않는다. 승격분은 전용 섹션에만 쓴다.
  - 관문: 허용(권위) 출처 · 충분한 요약 길이 · 웹페이지 군더더기 없음 · HTB 라이트업
    신호 없음 · 제어문자 없음. 하나라도 걸리면 그 항목은 승격하지 않는다.
  - 같은 출처 URL 은 새 내용으로 교체(중복 누적 없음), 주제당 항목 수 상한.
  - 승격분은 그 주제의 현재 카탈로그(learn.SOURCES) 출처만. 카탈로그에서 교체·삭제됐거나
    현재 관문을 통과하지 못하는 기존 승격 항목은 다음 승격 때 정리된다.
  - 시드 전문은 RAG 반영 상한(NOTE_CHARS) 안으로 유지(넘치면 오래된 승격분부터 버림).
  - CI 가 커밋된 시드의 승격 섹션을 같은 관문으로 재검사한다(tests/test_promote.py).
  - 가져온 내용은 신뢰불가 데이터 — 노트로만 저장, 실행·명령화하지 않는다.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import date

from . import learn

PROMOTED_HEADER = "## 최신 보강(승격)"
PROMOTED_NOTE = ("> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. "
                 "수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.")
MAX_ENTRIES = 3          # 주제당 승격 항목 상한(시드 비대화 방지)
MIN_SUMMARY = 120        # 이보다 짧은 요약은 정보가 부족하다고 본다
MAX_SUMMARY = 500        # 승격 시 요약 길이 상한(RAG 반영 상한 안에 시드 전문 유지)

# 요약 앞부분에 나타나면 본문이 아니라 웹페이지 군더더기로 보는 신호
_JUNK = re.compile(
    r"(?i)(enable javascript|javascript (is )?(disabled|required)|turn on javascript|"
    r"we use cookies|accept (all )?cookies|cookie (policy|settings)|skip to (main )?content|"
    r"thank you for visiting|we have migrated|\bmy account\b|\bproducts\b.{0,40}\bsolutions\b|\bsign in\b.{0,40}\b(sign up|register)\b)")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_ENTRY_TITLE = re.compile(r"^#{2,3} (.+)$")


@dataclass
class Candidate:
    title: str
    url: str = ""
    summary: str = ""
    promoted_on: str = ""


@dataclass
class PromoteResult:
    topic: str
    accepted: list[Candidate] = field(default_factory=list)
    rejected: list[tuple[str, str]] = field(default_factory=list)   # (제목, 사유)
    seed_path: str = ""
    pruned: list[tuple[str, str]] = field(default_factory=list)     # (제목, 사유) 시드에서 정리된 항목
    changed: bool = False
    error: str = ""


def check_candidate(c: Candidate) -> str | None:
    """승격 관문. 통과하면 None, 아니면 거부 사유."""
    if not c.url:
        return "출처 URL 없음"
    if not learn.is_allowed(c.url):
        return "허용(권위) 출처 아님"
    if _CONTROL.search(c.title + c.url + c.summary):
        return "제어문자 포함"
    if not c.summary.strip():
        return "요약 없음(오프라인 수집 등)"
    if len(c.summary.strip()) < MIN_SUMMARY:
        return f"요약이 너무 짧음(<{MIN_SUMMARY}자)"
    if _JUNK.search(c.summary[:150]):
        return "웹페이지 군더더기 의심"
    from .web_search import is_htb_writeup
    if is_htb_writeup(c.url, c.title, c.summary):
        return "HTB 라이트업 신호"
    return None


def _parse_entries(lines: list[str]) -> list[Candidate]:
    """'## 제목' 또는 '### 제목' + '- 출처: / - 요약: / - 승격일:' 블록을 읽는다."""
    out: list[Candidate] = []
    cur: Candidate | None = None
    for line in lines:
        m = _ENTRY_TITLE.match(line.rstrip())
        if m:
            cur = Candidate(title=m.group(1).strip())
            out.append(cur)
            continue
        if cur is None:
            continue
        s = line.strip()
        for key, attr in (("- 출처:", "url"), ("- 요약:", "summary"), ("- 승격일:", "promoted_on")):
            if s.startswith(key):
                setattr(cur, attr, s[len(key):].strip())
    return out


def parse_learned(text: str) -> list[Candidate]:
    """learned-<주제>.md 의 항목들."""
    return _parse_entries(text.splitlines())


def _norm(text: str) -> str:
    return text.replace("\r\n", "\n")


def split_seed(text: str) -> tuple[str, list[Candidate]]:
    """시드를 (사람이 쓴 본문, 승격 항목 전부) 로 나눈다.
    승격 섹션 뒤에 사람이 덧붙인 '## ' 절이 있으면 본문으로 보존한다(다음 승격 때 승격 섹션
    앞으로 옮겨질 뿐 지워지지 않음). 출처 없는 항목도 돌려줘 관문이 걸러내게 한다."""
    text = _norm(text)
    idx = text.find(PROMOTED_HEADER)
    if idx < 0:
        return text.rstrip() + "\n", []
    before = text[:idx].rstrip()
    section, tail = [], []
    for line in text[idx + len(PROMOTED_HEADER):].splitlines():
        if tail or (line.startswith("## ") and not line.startswith("### ")):
            tail.append(line)
        else:
            section.append(line)
    body = before + ("\n\n" + "\n".join(tail).strip() if "".join(tail).strip() else "")
    return body.rstrip() + "\n", _parse_entries(section)


def render_seed(body: str, entries: list[Candidate]) -> str:
    if not entries:
        return body
    lines = [body.rstrip(), "", PROMOTED_HEADER, "", PROMOTED_NOTE, ""]
    for c in entries:
        lines += [f"### {c.title}", f"- 출처: {c.url}"]
        if c.promoted_on:
            lines.append(f"- 승격일: {c.promoted_on}")
        lines += [f"- 요약: {c.summary}", ""]
    return "\n".join(lines).rstrip() + "\n"


def stray_lines(text: str) -> list[str]:
    """승격 섹션 안에서 항목 형식(### 제목 / - 출처·승격일·요약 / 안내문)에 속하지 않는 줄.
    promote 는 이런 줄이 있으면 지우지 않고 중단한다(사람이 쓴 내용 보호)."""
    text = _norm(text)
    idx = text.find(PROMOTED_HEADER)
    if idx < 0:
        return []
    out = []
    for line in text[idx + len(PROMOTED_HEADER):].splitlines():
        s = line.strip()
        if line.startswith("## ") and not line.startswith("### "):
            break                 # 뒤따르는 사람의 절 — 보존 대상
        if (not s or s == PROMOTED_NOTE or _ENTRY_TITLE.match(line.rstrip())
                or s.startswith(("- 출처:", "- 요약:", "- 승격일:"))):
            continue
        out.append(s)
    return out


def is_canonical(text: str) -> bool:
    """승격 섹션이 promote 가 쓰는 형식 그대로인가(섹션 안 임의 문장·출처 없는 항목 등 차단)."""
    if PROMOTED_HEADER not in text:
        return True
    body, entries = split_seed(text)
    def lines(t: str) -> list[str]:   # 줄 끝 공백 차이는 무시(무해)
        return [ln.rstrip() for ln in _norm(t).rstrip().splitlines()]
    return lines(text) == lines(render_seed(body, entries))


def merge(existing: list[Candidate], new: list[Candidate]) -> list[Candidate]:
    """기존 항목은 제자리에서 같은 URL 의 새 내용으로 교체하고, 처음 보는 URL 만 앞에
    붙인다(일시적 수집 실패로 순서가 바뀌는 diff 방지). 상한을 넘으면 뒤(오래된 것)부터 버림."""
    fresh: dict[str, Candidate] = {}
    for c in new:
        fresh.setdefault(c.url, c)
    known = {e.url for e in existing}
    out: list[Candidate] = []
    seen: set[str] = set()
    for c in [c for u, c in fresh.items() if u not in known] + [fresh.get(e.url, e) for e in existing]:
        if c.url in seen:
            continue
        seen.add(c.url)
        out.append(c)
    return out[:MAX_ENTRIES]


def promote(topic: str, learned_dir: str, seed_dir: str,
            today: str | None = None) -> PromoteResult:
    """주제 하나를 승격. 반영할 항목이나 정리할 항목이 있을 때만 시드를 다시 쓴다."""
    from .knowledge import NOTE_CHARS
    key = topic.strip().lower()
    res = PromoteResult(topic=key)
    if key not in learn.topics():
        res.error = "지원 주제 아님(--learn list 참고)"
        return res
    lpath = os.path.join(learned_dir, f"learned-{key}.md")
    spath = os.path.join(seed_dir, f"seed-{key}.md")
    res.seed_path = spath
    if not os.path.isfile(lpath):
        res.error = f"학습 노트 없음 — 먼저 'assassin --learn {key}' 실행"
        return res
    if not os.path.isfile(spath):
        res.error = "번들 시드 없음"
        return res
    stamp = today or date.today().isoformat()
    catalog = {u for _, u in learn.SOURCES.get(key, [])}
    with open(lpath, encoding="utf-8", errors="replace") as f:
        cands = parse_learned(f.read())
    seen: set[str] = set()
    for c in cands:
        c.summary = re.sub(r"\s+", " ", c.summary).strip()   # 정규화한 뒤에 관문 검사
        reason = check_candidate(c)
        if not reason and c.url not in catalog:
            reason = "현재 카탈로그에 없는 출처(교체·삭제됨 — 다시 --learn)"
        if not reason and c.url in seen:
            reason = "같은 출처 중복(앞 항목만 사용)"
        if reason:
            res.rejected.append((c.title, reason))
            continue
        seen.add(c.url)
        c.summary = c.summary[:MAX_SUMMARY].strip()
        c.promoted_on = stamp
        res.accepted.append(c)
    with open(spath, encoding="utf-8") as f:
        old = f.read()
    stray = stray_lines(old)
    if stray:
        res.error = (f"승격 섹션 안에 형식 밖 문장 {len(stray)}줄 — 지우지 않고 중단"
                     f"(예: {stray[0][:40]!r}). 본문으로 옮기거나 '## ' 절로 분리 후 재실행")
        return res
    body, existing = split_seed(old)
    kept: list[Candidate] = []
    for e in existing:            # 기존 승격분도 현재 카탈로그·관문으로 다시 확인
        why = ("카탈로그에서 빠진 출처" if e.url not in catalog else check_candidate(e))
        if why:
            res.pruned.append((e.title, why))
        else:
            kept.append(e)
    if not res.accepted and not res.pruned:
        return res
    prev = {e.url: e for e in kept}
    for c in res.accepted:        # 내용이 같으면 최초 승격일 유지(주기 실행 시 날짜만 바뀌는 diff 방지)
        old_e = prev.get(c.url)
        if old_e and old_e.title == c.title and old_e.summary == c.summary and old_e.promoted_on:
            c.promoted_on = old_e.promoted_on
    entries = merge(kept, res.accepted)
    new_text = render_seed(body, entries)
    while len(new_text) > NOTE_CHARS and entries:   # RAG 반영 상한(전문 로드) 안으로
        dropped = entries.pop()
        res.pruned.append((dropped.title, f"시드 길이 상한({NOTE_CHARS}자)"))
        new_text = render_seed(body, entries)
    if new_text != _norm(old):
        with open(spath, "w", encoding="utf-8") as f:
            f.write(new_text)
        res.changed = True
    return res


def promote_all(learned_dir: str, seed_dir: str, today: str | None = None) -> list[PromoteResult]:
    """학습 노트가 있는 모든 지원 주제를 승격 시도."""
    return [promote(t, learned_dir, seed_dir, today) for t in learn.topics()
            if os.path.isfile(os.path.join(learned_dir, f"learned-{t}.md"))]
