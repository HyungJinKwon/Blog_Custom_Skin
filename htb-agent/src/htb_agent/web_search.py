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

from .learn import ALLOWED_DOMAINS, extract_text

# ── 출처 신뢰 등급(교차검증용) ──
# Tier A(권위): learn.py 허용도메인 + NVD 등 — 내재적으로 검증된 1차 권위 출처.
TRUST_A_HOSTS = tuple(ALLOWED_DOMAINS) + (
    "nvd.nist.gov", "cve.mitre.org", "csrc.nist.gov",
)
# Tier B(평판): 널리 신뢰되는 기관·벤더·참조. 단독으로도 비교적 신뢰.
TRUST_B_HOSTS = (
    "nist.gov", "cisa.gov", "sans.org", "learn.microsoft.com", "docs.microsoft.com",
    "redhat.com", "access.redhat.com", "ubuntu.com", "debian.org", "kernel.org",
    "cloudflare.com", "wikipedia.org", "rapid7.com", "tenable.com", "snyk.io",
    "github.com", "gitlab.com", "python.org", "mozilla.org", "ietf.org",
    "first.org", "schneier.com", "acunetix.com", "invicti.com",
)
# 보안 관련성 게이트 — 동음이의(신화·천체 등) 비보안 문서를 걸러낸다.
_SEC_TERMS = re.compile(
    r"(?i)(secur|attack|vulnerab|exploit|authenticat|protocol|network|server|"
    r"malware|hash|password|credential|encrypt|privilege|injection|cve|cwe|"
    r"보안|공격|취약|인증|프로토콜|악성|권한)")


def is_security_relevant(text: str) -> bool:
    """본문에 보안 맥락 용어가 2개 이상 있으면 관련 문서로 본다."""
    return len(set(m.group(0).lower() for m in _SEC_TERMS.finditer(text or ""))) >= 2


_STOP = {
    "the", "and", "for", "with", "that", "this", "from", "are", "was", "can", "has",
    "will", "not", "you", "your", "they", "which", "when", "where", "what", "how",
    "a", "an", "is", "to", "of", "in", "on", "or", "be", "by", "as", "it", "its",
    "수", "있다", "있는", "등", "및", "이", "그", "저", "것", "통해", "대한", "하는",
}

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


def _reg_domain(host: str) -> str:
    """등록 도메인 근사(마지막 두 레이블) — 교차검증의 '독립 호스트' 판정용."""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def trust_tier(url: str) -> str:
    """출처 신뢰 등급: 'A'(권위) / 'B'(평판) / 'C'(일반)."""
    host = _host(url)
    if any(host == h or host.endswith("." + h) for h in TRUST_A_HOSTS):
        return "A"
    if any(host == h or host.endswith("." + h) for h in TRUST_B_HOSTS):
        return "B"
    return "C"


def _salient(text: str, limit: int = 60) -> set[str]:
    """교차검증용 핵심 토큰 집합(소문자, 길이>=4, 불용어 제외, 등장순 상한)."""
    seen: list[str] = []
    for t in re.findall(r"[A-Za-z가-힣0-9]{4,}", (text or "").lower()):
        if t not in _STOP and t not in seen:
            seen.append(t)
        if len(seen) >= limit:
            break
    return set(seen)


@dataclass
class WebResult:
    title: str
    url: str
    snippet: str = ""
    tier: str = "C"          # 신뢰 등급 A/B/C
    corroborators: int = 0   # 교차확인된 독립 호스트 수


@dataclass
class WebLearnResult:
    query: str
    refs: list[WebResult] = field(default_factory=list)    # 교차검증 통과(채택) 결과
    blocked: list[str] = field(default_factory=list)        # HTB 라이트업 가드 차단 URL
    unverified: list[str] = field(default_factory=list)     # 교차검증 실패(미채택) URL
    note_path: str = ""
    excerpt: str = ""

    def summary(self) -> str:
        if not self.refs and not self.blocked and not self.unverified:
            return f"'{self.query}' — 웹 학습 결과 없음"
        lines = [f"웹 학습: {self.query} — 검증채택 {len(self.refs)} / "
                 f"미검증 {len(self.unverified)} / HTB차단 {len(self.blocked)}"]
        for r in self.refs:
            lines.append(f"  · [{r.tier}] {r.title} — {r.url} (교차확인 {r.corroborators})")
        return "\n".join(lines)


# 설명적 User-Agent(위키미디어 등 정책 준수 — 빈약한 UA 는 429 유발).
_UA = "assassin-weblearn/1.0 (authorized HTB study agent; +https://github.com/HyungJinKwon)"


def _default_fetcher(timeout: int = 8, delay: float = 0.4) -> Callable[[str], str | None]:
    """정중한 fetch — 요청 간 최소 간격 + 429(레이트리밋) 시 Retry-After 존중 1회 재시도."""
    import time
    last = [0.0]

    def _get(url: str) -> str | None:
        from .util import network_blocked
        if network_blocked():
            return None
        import urllib.error
        import urllib.request
        for attempt in range(2):
            gap = delay - (time.monotonic() - last[0])
            if gap > 0:
                time.sleep(gap)
            last[0] = time.monotonic()
            req = urllib.request.Request(url, headers={"User-Agent": _UA})
            try:
                with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310
                    return r.read().decode("utf-8", "replace")
            except urllib.error.HTTPError as e:
                if e.code == 429 and attempt == 0:
                    try:
                        wait = min(float(e.headers.get("Retry-After", "2")), 10.0)
                    except (TypeError, ValueError):
                        wait = 2.0
                    time.sleep(wait)
                    continue
                return None
            except (urllib.error.URLError, OSError, ValueError):
                return None
        return None
    return _get


def wiki_search(query: str, fetch_fn: Callable[[str], str | None] | None = None,
                max_results: int = 5) -> list[WebResult]:
    """Wikipedia opensearch — 검색엔진 스크래핑이 막힌 환경의 신뢰 폴백(Tier B).
    기법/개념 질의에 안정적. 결과 (제목,URL,스니펫)."""
    import json
    fetch = fetch_fn or _default_fetcher()
    url = ("https://en.wikipedia.org/w/api.php?action=opensearch&limit="
           + str(max_results) + "&redirects=resolve&format=json&search="
           + urllib.parse.quote(query))
    raw = fetch(url)
    if not raw:
        return []
    try:
        d = json.loads(raw)
        titles, descs, urls = d[1], d[2], d[3]
    except (ValueError, IndexError, KeyError):
        return []
    out: list[WebResult] = []
    for i, u in enumerate(urls):
        t = titles[i] if i < len(titles) else ""
        s = descs[i] if i < len(descs) else ""
        out.append(WebResult(title=t, url=u, snippet=s))
    return out


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
    # 검색엔진이 결과를 안 주면(봇 차단 등) 신뢰 폴백(Wikipedia)로 보강.
    if not out:
        out = wiki_search(query, fetch, max_results)
    return out


def wiki_fetch(url: str, fetch_fn: Callable[[str], str | None], timeout: int = 8) -> str | None:
    """Wikipedia 문서는 extracts API 로 깔끔한 본문을 받는다(원 페이지 HTML 대신).
    그 외 URL 은 일반 fetch."""
    host = _host(url)
    if host.endswith("wikipedia.org") and "/wiki/" in url:
        import json
        title = urllib.parse.unquote(url.rsplit("/wiki/", 1)[-1])
        api = ("https://" + host + "/w/api.php?action=query&prop=extracts&exintro=1"
               "&explaintext=1&redirects=1&format=json&titles=" + urllib.parse.quote(title))
        raw = fetch_fn(api)
        if raw:
            try:
                pages = json.loads(raw)["query"]["pages"]
                ext = next(iter(pages.values())).get("extract", "")
                if ext.strip():
                    return "<p>" + ext + "</p>"
            except (ValueError, KeyError, StopIteration):
                pass
    return fetch_fn(url)


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
        """검색 → HTB 라이트업 가드 → 본문 수집 → **교차검증** → 통과분만 노트화.

        교차검증 규칙(§3 사실 기반·교차확인):
          · Tier A/B(권위·평판) 출처는 단독으로도 채택(내재적 검증).
          · Tier C(일반 블로그)는 **서로 다른 등록도메인 1곳 이상과 핵심 용어로
            corroborate(상호확인) 될 때만** 채택. 미확인 단독 C 는 미검증으로 제외.
        오프라인이면 수집 생략."""
        res = WebLearnResult(query=query)
        if not self.enabled:
            return res
        try:
            results = self._search(query)
        except Exception:   # noqa: BLE001 — 검색 실패가 풀이를 막지 않는다
            return res
        # 1) HTB 라이트업 차단 + 본문 수집(후보)
        cand: list[tuple[WebResult, str, set]] = []
        for r in results:
            if is_htb_writeup(r.url, r.title, r.snippet):
                res.blocked.append(r.url)
                continue
            if len(cand) >= max(self.max_pages + 2, 5):   # 교차검증 위해 약간 더 수집
                break
            raw = wiki_fetch(r.url, self.fetch)
            body = extract_text(raw, limit=1500) if raw else ""
            if body and is_htb_writeup(r.url, r.title, body):
                res.blocked.append(r.url)                 # 본문 2차 차단
                continue
            if body and not is_security_relevant(body):
                res.unverified.append(r.url)              # 비보안 동음이의 문서 → 제외
                continue
            if body:
                cand.append((r, body, _salient(body)))
        # 2) 교차검증 — 등급 + 독립 호스트 corroboration
        picked: list[tuple[WebResult, str]] = []
        for i, (r, body, terms) in enumerate(cand):
            r.tier = trust_tier(r.url)
            dom_i = _reg_domain(_host(r.url))
            corrob = 0
            for j, (r2, _b2, terms2) in enumerate(cand):
                if i == j or _reg_domain(_host(r2.url)) == dom_i:
                    continue                              # 다른 등록도메인만 독립 출처
                if len(terms & terms2) >= 4:              # 핵심 용어 4개 이상 공유 → 상호확인
                    corrob += 1
            r.corroborators = corrob
            verified = r.tier in ("A", "B") or corrob >= 1
            if verified and len(picked) < self.max_pages:
                picked.append((r, body))
                res.refs.append(r)
            elif not verified:
                res.unverified.append(r.url)              # 단독 미확인 C → 제외
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
                     "> 인터넷 검색 학습(assassin --web-learn). 교차검증 통과분만 수록 — "
                     "Tier A/B(권위·평판) 또는 독립 출처 상호확인(corroborated). "
                     "HTB 라이트업(공식·제3자)은 가드로 제외. 신뢰불가 데이터(노트 저장만).",
                     ""]
            for r, body in picked:
                lines.append(f"## [{r.tier}급·교차확인{r.corroborators}] {r.title}")
                lines.append(f"- 출처: {r.url}")
                lines.append(f"- 요약: {body}")
                lines.append("")
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            return path
        except OSError:
            return ""
