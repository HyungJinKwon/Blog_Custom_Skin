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
# 제품명(대문자로 시작하는 단어) 바로 뒤의 '단독 major'(점표기 아님) — 예: 'FreePBX 16',
# 'Drupal 7'. 점표기 버전이 없는 제목도 major 단위로 대략 대조하기 위한 것(뒤에 ./숫자가
# 오면 점표기이므로 제외). CVE 연도·'(2)' 같은 괄호 숫자는 앞이 글자가 아니라 걸리지 않는다.
_MAJOR_RE = re.compile(r"[A-Za-z]{2,}\s+(\d{1,3})(?![\d.])")
# 헤더·구분선·섹션 제목은 데이터 행이 아니다.
_SKIP = ("exploit title", "shellcode title", "paper title")


@dataclass
class SploitHit:
    title: str
    locator: str = ""                       # exploit-db 경로 또는 URL
    versions: list[str] = field(default_factory=list)   # 제목에서 뽑은 버전들

    def __str__(self) -> str:
        return f"{self.title}  →  {self.locator}" if self.locator else self.title


# 한 항목 = '제목 | locator'. locator 는 exploit-db 경로(platform/type/NNNNN.ext) 또는
# -w 의 URL. 요약기가 줄바꿈을 공백으로 합쳐도(정상 동작) 각 locator 가 고유 토큰이라
# finditer 로 항목을 안전히 분리한다(라인 기반이 아니라 토큰 기반 → collapsed 출력에도 견고).
_ROW_RE = re.compile(r"([^|]+?)\s*\|\s*((?:https?://\S+)|(?:[\w./+-]+/\d{3,7}\.\w+))")


def parse_searchsploit(text: str) -> list[SploitHit]:
    """searchsploit 표 출력 → SploitHit 목록(제목·locator·버전). 빈/무결과는 [].
    라인 기반이 아니라 '제목 | locator' 토큰을 정규식으로 뽑아, 요약으로 줄바꿈이 공백이
    된 출력에서도 각 항목을 정확히 분리한다(헤더 'Exploit Title | Path'·구분선은 locator 가
    경로/URL 아니라 자연히 제외)."""
    if not text:
        return []
    hits: list[SploitHit] = []
    seen: set[str] = set()
    for m in _ROW_RE.finditer(text):
        title = re.sub(r"\s+", " ", m.group(1)).strip()
        # 요약 접두('searchsploit: N건 —')·항목 구분자(';')·컬럼 헤더('Path'/'URL')·구분선
        # 대시가 제목 앞에 붙을 수 있어 제거(제목 중간의 ' - ' 는 보존 — 선행만 정리).
        title = re.sub(r"^\s*searchsploit:\s*\d+\S*\s*—\s*", "", title)
        title = re.sub(r"^(?:Exploit Title|Path|URL)\b\s*", "", title).lstrip(";- ").strip()
        locator = m.group(2).strip()
        if not title or title.lower() in _SKIP:
            continue
        if title in seen:
            continue
        seen.add(title)
        vers = _VER_RE.findall(title)
        # 제품명 뒤 단독 major(예: 'FreePBX 16')를 보강 — 이미 같은 major 의 점표기 버전이
        # 있으면 추가하지 않는다(중복·노이즈 억제). 대상 '16.0.40.7' ↔ 제목 '16' 대조용.
        for mm in _MAJOR_RE.finditer(title):
            maj = mm.group(1)
            if not any(v.split(".")[0] == maj for v in vers):
                vers.append(maj)
        hits.append(SploitHit(title, locator, vers))
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


def has_version_match(hits: list[SploitHit], version: str) -> bool:
    """후보 중 '대상 버전'과 접두 호환되는 익스가 하나라도 있으면 True(⭐ 자동 선택 신뢰 조건).
    버전 미상이면 False — 이때는 1순위를 함부로 '자동 선택'으로 표시하지 않는다."""
    return bool(version) and any(_version_matches(h.versions, version) for h in hits)


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
