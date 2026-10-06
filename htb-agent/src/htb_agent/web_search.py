"""
Open Web Learner — 인터넷 검색 기반 학습 (HTB 라이트업 가드)
=============================================================

`learn.py` 가 고정 허용도메인만 가져오는 것과 달리, 이 모듈은 **넓은 인터넷 검색**으로
개념·기법을 학습한다. 단 하나의 강한 가드가 항상 적용된다.

  ❌ **HTB 머신 라이트업은 출처 불문 전부 차단** — 공식(hackthebox.com)이든 제3자
     (0xdf·ippsec·htbmachines·블로그·유튜브)이든, "HTB <머신> writeup/walkthrough/풀이"
     형태의 콘텐츠는 가져오지 않는다. HTB 라이트업은 오직 **사용자가 직접 ingest 로
     제공한 것만** 지식베이스에 들어온다(learn.ingest).
  ✅ 그 외 일반 학습(기법 설명 아티클·공식 문서·비-HTB 콘텐츠)은 허용.

안전 설계(기존 모델 유지):
  - **주입식 fetch/search** — 네트워크 분리(오프라인/테스트 안전). 라이브 수집은 사용자
    Kali 등 개방망에서 동작, 이 클라우드(egress 제한)에선 주입/오프라인으로 테스트.
  - 가져온 내용은 **신뢰 불가 데이터** — 노트로 저장만, 실행/명령화 안 함.
  - 산출물(learned-web-*.md)은 런타임 학습물 → .gitignore(세션/로컬 한정).
"""
from __future__ import annotations

import os
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable

from .learn import extract_text

# HTB 라이트업 전용/빈출 호스트 — 이 호스트의 결과는 HTB 라이트업으로 간주해 차단.
HTB_WRITEUP_HOSTS = (
    "0xdf.gitlab.io", "ippsec.rocks", "htbmachines.com", "htbwriteup",
    "hackthebox.com", "app.hackthebox.com", "ctf.0xdf",
)
# HTB 신호 — 이 중 하나라도 있으면 'HTB 맥락'.
_HTB_SIGNAL = re.compile(r"(?i)\b(hack\s*the\s*box|hackthebox|htb)\b")
# 라이트업/풀이 신호.
_WRITEUP_SIGNAL = re.compile(
    r"(?i)(write[\s-]?up|walk[\s-]?through|라이트업|풀이|워크스루|machine\s+(?:writeup|walkthrough))")


def is_htb_writeup(url: str, title: str = "", snippet: str = "") -> bool:
    """HTB 머신 라이트업(공식·제3자 불문)으로 판단되면 True → 웹학습에서 차단.
    보수적: HTB 맥락 + 라이트업 신호가 함께 있으면, 또는 알려진 라이트업 호스트면 차단."""
    blob = f"{url}\n{title}\n{snippet}"
    host = _host(url)
    if any(h in host for h in HTB_WRITEUP_HOSTS):
        return True
    # hackthebox.com 등 HTB 도메인 전반(공식 라이트업 포함) 차단
    if "hackthebox" in host:
        return True
    # HTB 맥락 + 라이트업/풀이 신호 → 제3자 HTB 라이트업
    if _HTB_SIGNAL.search(blob) and _WRITEUP_SIGNAL.search(blob):
        return True
    return False


def _host(url: str) -> str:
    m = re.match(r"https?://([^/]+)", url or "", re.I)
    return (m.group(1).lower() if m else "").split(":")[0]


@dataclass
class WebResult:
    title: str
    url: str
    snippet: str = ""


@dataclass
class WebLearnResult:
    query: str
    refs: list[WebResult] = field(default_factory=list)   # 학습에 사용한 결과
    blocked: list[str] = field(default_factory=list)       # 라이트업 가드로 차단된 URL
    note_path: str = ""
    excerpt: str = ""

    def summary(self) -> str:
        if not self.refs and not self.blocked:
            return f"'{self.query}' — 웹 학습 결과 없음"
        lines = [f"웹 학습: {self.query} — 채택 {len(self.refs)} / 차단 {len(self.blocked)}"]
        for r in self.refs:
            lines.append(f"  · {r.title} — {r.url}")
        if self.blocked:
            lines.append(f"  (HTB 라이트업 차단: {len(self.blocked)}건)")
        return "\n".join(lines)


def _default_fetcher(timeout: int = 8) -> Callable[[str], str | None]:
    def _get(url: str) -> str | None:
        import urllib.error
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 assassin-weblearn/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310
                return r.read().decode("utf-8", "replace")
        except (urllib.error.URLError, OSError, ValueError):
            return None
    return _get


# DuckDuckGo HTML 결과 링크(우회 리다이렉트 uddg= 포함) 파서.
_RESULT_A = re.compile(r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
                       re.I | re.S)
_SNIPPET = re.compile(r'class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</a>', re.I | re.S)
_TAGS = re.compile(r"<[^>]+>")


def _decode_ddg(href: str) -> str:
    """DuckDuckGo 리다이렉트(//duckduckgo.com/l/?uddg=...) → 실제 URL."""
    if "uddg=" in href:
        q = urllib.parse.urlparse(href if href.startswith("http") else "https:" + href).query
        params = urllib.parse.parse_qs(q)
        if "uddg" in params:
            return params["uddg"][0]
    return href if href.startswith("http") else ("https:" + href if href.startswith("//") else href)


def search(query: str, fetch_fn: Callable[[str], str | None] | None = None,
           max_results: int = 8) -> list[WebResult]:
    """DuckDuckGo HTML 엔드포인트로 검색(주입식 fetch 가능). 결과 (제목,URL,스니펫) 목록."""
    fetch = fetch_fn or _default_fetcher()
    url = "https://html.duckduckgo.com/html/?q=" + urllib.parse.quote(query)
    html = fetch(url)
    if not html:
        return []
    out: list[WebResult] = []
    snippets = _SNIPPET.findall(html)
    for i, (href, title_html) in enumerate(_RESULT_A.findall(html)):
        real = _decode_ddg(href)
        title = _TAGS.sub("", title_html).strip()
        snip = _TAGS.sub("", snippets[i]).strip() if i < len(snippets) else ""
        if real.startswith("http"):
            out.append(WebResult(title=title, url=real, snippet=snip))
        if len(out) >= max_results:
            break
    return out


class WebLearner:
    """인터넷 검색 학습기. HTB 라이트업은 항상 차단(block_htb_writeups)."""

    def __init__(self, cache_dir: str = "knowledge/notes/learned",
                 fetch_fn: Callable[[str], str | None] | None = None,
                 search_fn: Callable[[str], list[WebResult]] | None = None,
                 enabled: bool = True, max_pages: int = 3, timeout: int = 8):
        self.cache_dir = cache_dir
        self.enabled = enabled
        self.max_pages = max_pages
        self.fetch = fetch_fn or _default_fetcher(timeout)
        self._search = search_fn or (lambda q: search(q, self.fetch))

    def learn(self, query: str) -> WebLearnResult:
        """검색 → HTB 라이트업 가드 통과분만 본문 추출 → 노트화. 오프라인이면 수집 생략."""
        res = WebLearnResult(query=query)
        if not self.enabled:
            return res
        try:
            results = self._search(query)
        except Exception:   # noqa: BLE001 — 검색 실패가 풀이를 막지 않는다
            return res
        picked: list[tuple[WebResult, str]] = []
        for r in results:
            if is_htb_writeup(r.url, r.title, r.snippet):
                res.blocked.append(r.url)        # HTB 라이트업 → 차단(가져오지 않음)
                continue
            if len(picked) >= self.max_pages:
                continue
            raw = self.fetch(r.url)
            body = extract_text(raw, limit=1500) if raw else ""
            # 본문에서도 HTB 라이트업 신호 재확인(스니펫만으로 놓친 경우 2차 차단)
            if body and is_htb_writeup(r.url, r.title, body):
                res.blocked.append(r.url)
                continue
            if body:
                picked.append((r, body))
                res.refs.append(r)
        if picked:
            res.excerpt = " … ".join(b for _, b in picked)[:1500]
            res.note_path = self._write_note(query, picked)
        return res

    def _write_note(self, query: str, picked: list[tuple[WebResult, str]]) -> str:
        slug = re.sub(r"[^a-zA-Z0-9_.-]", "_", query.strip().lower())[:60] or "query"
        path = os.path.join(self.cache_dir, f"learned-web-{slug}.md")
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
            lines = [f"# 웹 학습 노트: {query}", "",
                     "> 인터넷 검색 학습(assassin --web-learn). 일반 기법/문서 — "
                     "HTB 라이트업(공식·제3자)은 가드로 제외. 신뢰불가 데이터(노트 저장만).",
                     ""]
            for r, body in picked:
                lines.append(f"## {r.title}")
                lines.append(f"- 출처: {r.url}")
                lines.append(f"- 요약: {body}")
                lines.append("")
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            return path
        except OSError:
            return ""
