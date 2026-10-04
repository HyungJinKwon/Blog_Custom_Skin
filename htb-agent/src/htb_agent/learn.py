"""
Reference Learner — 권위 출처 자가학습 (Option A, P1 유지)
==========================================================

도구 사용법·공격 기법·개념/정의·프로토콜을 **권위 있는 공식 출처에서만** 가져와
지식베이스 노트로 축적한다. 특정 머신/문제의 공개 라이트업·워크스루는 **절대**
가져오지 않는다(P1 준수). NVD 기반 CVE 수집(enrich.py)과 같은 철학:
"권위 레퍼런스는 허용, 문제 풀이 인용은 금지."

안전 설계:
  - **허용 도메인(allowlist)** 외 URL 은 가져오지 않는다(하드 차단).
  - **주입식 fetcher** — 네트워크 분리(오프라인/테스트 안전). 실패/오프라인이면
    출처 포인터(제목+URL)만 노트로 남긴다(본문 없이).
  - 가져온 내용은 **신뢰 불가 데이터** — 노트로 저장만, 실행/명령화 안 함.
  - 캐시(재수집 방지). 출처 URL 을 노트에 반드시 표기(§5 출처).
"""
from __future__ import annotations

import html as _html
import os
import re
from dataclasses import dataclass, field
from typing import Callable

# 허용 도메인(권위 출처만). 이 목록 밖은 가져오지 않는다.
ALLOWED_DOMAINS = (
    "attack.mitre.org", "cwe.mitre.org", "capec.mitre.org",
    "owasp.org", "cheatsheetseries.owasp.org",
    "portswigger.net",            # Burp Suite 공식 + Web Security Academy
    "www.wireshark.org", "wiki.wireshark.org",
    "nmap.org",
    "datatracker.ietf.org",       # RFC(프로토콜 정의)
    "developer.mozilla.org",      # 웹/HTTP 개념
)

# 주제 카탈로그: 키워드 → [(제목, URL)]. 전부 권위 공식 출처.
SOURCES: dict[str, list[tuple[str, str]]] = {
    # 도구
    "burp": [("Burp Suite 문서", "https://portswigger.net/burp/documentation"),
             ("Web Security Academy", "https://portswigger.net/web-security")],
    "wireshark": [("Wireshark User's Guide", "https://www.wireshark.org/docs/wsug_html_chunked/"),
                  ("Display Filter Reference", "https://www.wireshark.org/docs/dfref/")],
    "nmap": [("Nmap Reference Guide", "https://nmap.org/book/man.html"),
             ("NSE 문서", "https://nmap.org/book/nse.html")],
    # 공격 기법(MITRE ATT&CK)
    "kerberoasting": [("ATT&CK T1558.003 Kerberoasting",
                       "https://attack.mitre.org/techniques/T1558/003/")],
    "as-rep": [("ATT&CK T1558.004 AS-REP Roasting",
                "https://attack.mitre.org/techniques/T1558/004/")],
    "pass-the-hash": [("ATT&CK T1550.002 Pass the Hash",
                       "https://attack.mitre.org/techniques/T1550/002/")],
    "dcsync": [("ATT&CK T1003.006 DCSync",
                "https://attack.mitre.org/techniques/T1003/006/")],
    "privilege-escalation": [("ATT&CK TA0004 Privilege Escalation",
                              "https://attack.mitre.org/tactics/TA0004/")],
    "lateral-movement": [("ATT&CK TA0008 Lateral Movement",
                          "https://attack.mitre.org/tactics/TA0008/")],
    # 개념/정의(웹 취약점)
    "sqli": [("OWASP SQL Injection", "https://owasp.org/www-community/attacks/SQL_Injection"),
             ("WSTG SQLi", "https://portswigger.net/web-security/sql-injection")],
    "xss": [("OWASP XSS", "https://owasp.org/www-community/attacks/xss/"),
            ("PortSwigger XSS", "https://portswigger.net/web-security/cross-site-scripting")],
    "ssrf": [("PortSwigger SSRF", "https://portswigger.net/web-security/ssrf"),
             ("OWASP SSRF", "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery")],
    "lfi": [("OWASP Path Traversal", "https://owasp.org/www-community/attacks/Path_Traversal")],
    "deserialization": [("OWASP Deserialization",
                         "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html")],
    # 프로토콜/네트워크(RFC·MDN)
    "http": [("HTTP(MDN)", "https://developer.mozilla.org/en-US/docs/Web/HTTP"),
             ("RFC 9110 HTTP Semantics", "https://datatracker.ietf.org/doc/html/rfc9110")],
    "dns": [("RFC 1035 DNS", "https://datatracker.ietf.org/doc/html/rfc1035")],
    "kerberos": [("RFC 4120 Kerberos V5", "https://datatracker.ietf.org/doc/html/rfc4120")],
    "ldap": [("RFC 4511 LDAP", "https://datatracker.ietf.org/doc/html/rfc4511")],
    "tls": [("RFC 8446 TLS 1.3", "https://datatracker.ietf.org/doc/html/rfc8446")],
    "smb": [("ATT&CK SMB/Windows Admin Shares",
             "https://attack.mitre.org/techniques/T1021/002/")],
}


@dataclass
class LearnedRef:
    title: str
    url: str
    excerpt: str = ""


@dataclass
class LearnResult:
    topic: str
    refs: list[LearnedRef] = field(default_factory=list)
    note_path: str = ""
    message: str = ""

    def summary(self) -> str:
        if not self.refs:
            return f"'{self.topic}' — 매칭 출처 없음. (지원 주제: {', '.join(sorted(SOURCES))})"
        lines = [f"학습: {self.topic} — {len(self.refs)}개 권위 출처"]
        for r in self.refs:
            lines.append(f"  · {r.title} — {r.url}"
                         + (f"\n    {r.excerpt[:160]}" if r.excerpt else ""))
        if self.note_path:
            lines.append(f"노트 저장: {self.note_path}")
        return "\n".join(lines)


def _default_fetcher(timeout: int = 6) -> Callable[[str], str | None]:
    def _get(url: str) -> str | None:
        import urllib.error
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent": "assassin-learn/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310 (allowlist)
                return r.read().decode("utf-8", "replace")
        except (urllib.error.URLError, OSError, ValueError):
            return None
    return _get


def _domain_of(url: str) -> str:
    m = re.match(r"https?://([^/]+)", url, re.I)
    return (m.group(1).lower() if m else "").split(":")[0]


def is_allowed(url: str) -> bool:
    """허용 도메인(정확 일치 또는 하위도메인)만 True."""
    d = _domain_of(url)
    return any(d == a or d.endswith("." + a) for a in ALLOWED_DOMAINS)


_TAG = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")


def extract_text(html_text: str, limit: int = 600) -> str:
    """HTML 에서 본문 텍스트만 거칠게 추출(script/style 제거 → 태그 제거 → 공백정리)."""
    if not html_text:
        return ""
    t = re.sub(r"(?is)<(script|style|head|nav|footer)[^>]*>.*?</\1>", " ", html_text)
    t = _TAG.sub(" ", t)
    t = _html.unescape(t)
    t = _WS.sub(" ", t).strip()
    return t[:limit]


class ReferenceLearner:
    def __init__(self, cache_dir: str = "knowledge/notes/learned",
                 fetch_fn: Callable[[str], str | None] | None = None,
                 enabled: bool = True, timeout: int = 6):
        self.cache_dir = cache_dir
        self.enabled = enabled
        self.fetch = fetch_fn or _default_fetcher(timeout)

    def match_sources(self, topic: str) -> list[tuple[str, str]]:
        """주제 키워드에 맞는 출처(부분일치·별칭 포함)."""
        key = topic.strip().lower()
        if key in SOURCES:
            return SOURCES[key]
        hits: list[tuple[str, str]] = []
        for k, refs in SOURCES.items():
            if key in k or k in key:
                hits.extend(refs)
        return hits

    def learn(self, topic: str) -> LearnResult:
        res = LearnResult(topic=topic)
        for title, url in self.match_sources(topic):
            if not is_allowed(url):     # 방어: 카탈로그 밖/오염 URL 차단
                continue
            excerpt = ""
            if self.enabled:
                raw = self.fetch(url)
                excerpt = extract_text(raw) if raw else ""
            res.refs.append(LearnedRef(title=title, url=url, excerpt=excerpt))
        if res.refs:
            res.note_path = self._write_note(res)
            res.message = "저장 완료" if self.enabled else "오프라인 — 출처 포인터만 저장"
        return res

    def _write_note(self, res: LearnResult) -> str:
        safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", res.topic.strip().lower()) or "topic"
        path = os.path.join(self.cache_dir, f"learned-{safe}.md")
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
            lines = [f"# 학습 노트: {res.topic} (권위 출처)",
                     "", "> 자동 수집(assassin --learn). 공식/권위 출처만 — 문제별 라이트업 미참조(P1).",
                     ""]
            for r in res.refs:
                lines.append(f"## {r.title}")
                lines.append(f"- 출처: {r.url}")
                if r.excerpt:
                    lines.append(f"- 요약: {r.excerpt}")
                lines.append("")
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            return path
        except OSError:
            return ""


def topics() -> list[str]:
    return sorted(SOURCES)
