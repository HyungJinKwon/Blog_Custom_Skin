"""searchsploit 출력 파서 + 버전 매칭 — 조회 결과에서 '대상 버전에 맞는 공개 익스'를
추려 제시하기 위한 것(생성 전용, 파싱만 — 실행·다운로드 없음).

searchsploit 표 형식:
  --------------------------------- ---------------------------------
   Exploit Title                    | Path (또는 -w 의 URL)
  --------------------------------- ---------------------------------
   FreePBX 13.0.188 - Remote ...    | php/webapps/40434.py
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_VER_RE = re.compile(r"\d+(?:\.\d+){1,3}")
# 헤더·구분선·섹션 제목은 데이터 행이 아니다.
_SKIP = ("exploit title", "shellcode title", "paper title")


@dataclass
class SploitHit:
    title: str
    locator: str = ""                       # exploit-db 경로 또는 URL
    versions: list[str] = field(default_factory=list)   # 제목에서 뽑은 버전들

    def __str__(self) -> str:
        return f"{self.title}  →  {self.locator}" if self.locator else self.title


def parse_searchsploit(text: str) -> list[SploitHit]:
    """searchsploit 표 출력 → SploitHit 목록(제목·locator·버전). 빈 입력·무결과는 []
    (무결과면 데이터 행이 없어 자연히 [] — 'No Results' 문자열에 전역 의존하지 않는다)."""
    if not text:
        return []
    hits: list[SploitHit] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or "|" not in line:
            continue
        if set(line) <= set("- "):          # 구분선
            continue
        title, _, locator = line.rpartition("|")
        title, locator = title.strip(), locator.strip()
        if not title or title.lower() in _SKIP or locator.lower() in ("path", "url"):
            continue
        if title in seen:
            continue
        seen.add(title)
        hits.append(SploitHit(title, locator, _VER_RE.findall(title)))
    return hits


def _version_matches(hit_versions: list[str], target: str) -> bool:
    """제목 버전 중 하나가 대상 버전과 접두 호환이면 True(예: 대상 13.0.188 ↔ 제목 13.0)."""
    if not target:
        return False
    tparts = target.split(".")
    for hv in hit_versions:
        hparts = hv.split(".")
        n = min(len(tparts), len(hparts))
        if n and tparts[:n] == hparts[:n]:
            return True
    return False


def shortlist(hits: list[SploitHit], version: str = "", limit: int = 6) -> list[SploitHit]:
    """대상 버전에 맞는 익스를 앞으로 정렬해 상위 N개. 버전 미상이면 원래 순서 상위 N개
    (대조는 사람/LLM 이 수행하도록 후보만 좁힌다). 실행·선택은 하지 않는다."""
    if not hits:
        return []
    if version:
        matched = [h for h in hits if _version_matches(h.versions, version)]
        if matched:
            rest = [h for h in hits if h not in matched]
            return (matched + rest)[:limit]
    return hits[:limit]
