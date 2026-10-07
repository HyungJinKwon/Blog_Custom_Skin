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
from html.parser import HTMLParser
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
             ("PortSwigger SQL Injection", "https://portswigger.net/web-security/sql-injection")],
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
    # 웹 취약점(추가) — PortSwigger Web Security Academy + OWASP
    "csrf": [("PortSwigger CSRF", "https://portswigger.net/web-security/csrf"),
             ("OWASP CSRF", "https://owasp.org/www-community/attacks/csrf")],
    "xxe": [("PortSwigger XXE", "https://portswigger.net/web-security/xxe"),
            ("OWASP XXE", "https://owasp.org/www-community/attacks/xxe")],
    "command-injection": [("PortSwigger OS Command Injection",
                           "https://portswigger.net/web-security/os-command-injection"),
                          ("OWASP Command Injection",
                           "https://owasp.org/www-community/attacks/Command_Injection")],
    "file-upload": [("PortSwigger File Upload",
                     "https://portswigger.net/web-security/file-upload"),
                    ("OWASP Unrestricted File Upload",
                     "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload")],
    "ssti": [("PortSwigger SSTI",
              "https://portswigger.net/web-security/server-side-template-injection")],
    "jwt": [("PortSwigger JWT", "https://portswigger.net/web-security/jwt"),
            ("OWASP JWT Cheat Sheet",
             "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html")],
    "access-control": [("PortSwigger Access Control (IDOR)",
                        "https://portswigger.net/web-security/access-control")],
    "authentication": [("PortSwigger Authentication",
                        "https://portswigger.net/web-security/authentication")],
    "cors": [("PortSwigger CORS", "https://portswigger.net/web-security/cors")],
    "request-smuggling": [("PortSwigger HTTP Request Smuggling",
                           "https://portswigger.net/web-security/request-smuggling")],
    "prototype-pollution": [("PortSwigger Prototype Pollution",
                             "https://portswigger.net/web-security/prototype-pollution")],
    "race-condition": [("PortSwigger Race Conditions",
                        "https://portswigger.net/web-security/race-conditions")],
    "nosql-injection": [("PortSwigger NoSQL Injection",
                         "https://portswigger.net/web-security/nosql-injection")],
    "graphql": [("PortSwigger GraphQL API", "https://portswigger.net/web-security/graphql")],
    "oauth": [("PortSwigger OAuth", "https://portswigger.net/web-security/oauth")],
    "web-cache-poisoning": [("PortSwigger Web Cache Poisoning",
                             "https://portswigger.net/web-security/web-cache-poisoning")],
    "clickjacking": [("PortSwigger Clickjacking",
                      "https://portswigger.net/web-security/clickjacking")],
    "path-traversal": [("PortSwigger Path Traversal",
                        "https://portswigger.net/web-security/file-path-traversal")],
    # 공격 전술/기법(추가) — MITRE ATT&CK
    "brute-force": [("ATT&CK T1110 Brute Force",
                     "https://attack.mitre.org/techniques/T1110/")],
    "service-discovery": [("ATT&CK T1046 Network Service Discovery",
                           "https://attack.mitre.org/techniques/T1046/")],
    "exploit-public-app": [("ATT&CK T1190 Exploit Public-Facing Application",
                            "https://attack.mitre.org/techniques/T1190/")],
    "exploitation-privesc": [("ATT&CK T1068 Exploitation for Privilege Escalation",
                              "https://attack.mitre.org/techniques/T1068/")],
    "valid-accounts": [("ATT&CK T1078 Valid Accounts",
                        "https://attack.mitre.org/techniques/T1078/")],
    "credential-dumping": [("ATT&CK T1003 OS Credential Dumping",
                            "https://attack.mitre.org/techniques/T1003/")],
    "persistence": [("ATT&CK TA0003 Persistence",
                     "https://attack.mitre.org/tactics/TA0003/")],
    "defense-evasion": [("ATT&CK TA0005 Defense Evasion",
                         "https://attack.mitre.org/tactics/TA0005/")],
    "exfiltration": [("ATT&CK TA0010 Exfiltration",
                      "https://attack.mitre.org/tactics/TA0010/")],
    # 프로토콜(추가) — IETF RFC
    "ftp": [("RFC 959 FTP", "https://datatracker.ietf.org/doc/html/rfc959")],
    "ssh": [("RFC 4253 SSH Transport", "https://datatracker.ietf.org/doc/html/rfc4253")],
    "snmp": [("RFC 1157 SNMP", "https://datatracker.ietf.org/doc/html/rfc1157")],
    "smtp": [("RFC 5321 SMTP", "https://datatracker.ietf.org/doc/html/rfc5321")],
    "tcp": [("RFC 9293 TCP", "https://datatracker.ietf.org/doc/html/rfc9293")],
    # HTB 특화 공격 체인(추가) — MITRE ATT&CK
    "pivoting": [("ATT&CK T1090 Proxy", "https://attack.mitre.org/techniques/T1090/")],
    "password-cracking": [("ATT&CK T1110.002 Password Cracking",
                           "https://attack.mitre.org/techniques/T1110/002/")],
    "pass-the-ticket": [("ATT&CK T1550.003 Pass the Ticket",
                         "https://attack.mitre.org/techniques/T1550/003/")],
    "golden-ticket": [("ATT&CK T1558.001 Golden Ticket",
                       "https://attack.mitre.org/techniques/T1558/001/")],
    "silver-ticket": [("ATT&CK T1558.002 Silver Ticket",
                       "https://attack.mitre.org/techniques/T1558/002/")],
    "ad-enumeration": [("ATT&CK T1087.002 Domain Account Discovery",
                        "https://attack.mitre.org/techniques/T1087/002/")],
    "unsecured-credentials": [("ATT&CK T1552 Unsecured Credentials",
                               "https://attack.mitre.org/techniques/T1552/")],
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


# ── 본문 추출 ─────────────────────────────────────────────────────────
# 문서 페이지에는 메뉴·헤더·푸터·쿠키 배너·"JavaScript 를 켜세요" 안내 같은 군더더기가
# 본문보다 앞에 온다. 정규식으로 태그만 벗기면 이것들이 요약 자리를 차지해, 노트가
# LLM 컨텍스트에 잡음으로 들어간다. 구조를 따라가며 군더더기 영역을 버리고, 본문
# 영역(<main>/<article>)이 있으면 그것을 우선한다.
_DROP_TAGS = {"script", "style", "noscript", "template", "svg", "head", "nav", "header",
              "footer", "aside", "form", "button", "select", "iframe", "dialog", "canvas"}
_DROP_ROLES = {"navigation", "banner", "contentinfo", "complementary", "search", "menu",
               "menubar", "dialog", "alertdialog"}
# class/id 토큰(-·_ 로 쪼갠 단어) 중 하나라도 이것이면 군더더기 영역
_DROP_CLASS_TOKENS = {"nav", "navbar", "navigation", "menu", "breadcrumb", "breadcrumbs",
                      "cookie", "cookies", "consent", "banner", "sidebar", "footer", "skip",
                      "toolbar", "share", "social", "newsletter", "subscribe", "masthead",
                      "alert", "collapsed", "toc"}   # 공지 배너 · 접힘 토글 머리 · 목차
_MAIN_TAGS = {"main", "article"}
_NEVER_ATTR_DROP = {"html", "body", "main", "article"}
_BLOCK_TAGS = {"p", "li", "h1", "h2", "h3", "h4", "h5", "h6", "pre", "td", "th", "dd", "dt",
               "blockquote", "div", "section", "article", "main", "tr", "table", "ul", "ol",
               "figcaption", "caption", "summary", "details"}
_VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
              "param", "source", "track", "wbr"}
# 짧은 블록에 한해 버리는 사이트 공통 고지문(본문 문장은 길어서 걸리지 않는다)
_BOILERPLATE = re.compile(
    r"(?i)(enable javascript|javascript (is )?(disabled|required)|turn on javascript|"
    r"we use cookies|this (web)?site uses cookies|accept (all )?cookies|cookie (policy|settings)|"
    r"skip to (main )?content|^(sign in|log ?in|my account|menu|search)$)")
# 작성자·기여자·갱신일 메타 줄(기여자 목록은 길 수 있어 별도 길이 상한)
_META_LINE = re.compile(r"(?i)^(author|contributor\(s\)|last updated)\s*:")
# RFC 는 본문 앞에 저자·번호·분류 머리글이 수백 자 온다 — 초록(없으면 'Status of this Memo')부터
_RFC_HEAD = re.compile(r"^(Network Working Group|Internet Engineering Task Force|"
                       r"Request for Comments|RFC \d+)\b")
_RFC_ABSTRACT = re.compile(r"\bAbstract\b")
_RFC_STATUS = re.compile(r"(?i)\bStatus of this Memo\b")


def _drop_by_attrs(attrs: list[tuple[str, str | None]]) -> bool:
    d = {k.lower(): (v or "") for k, v in attrs}
    if d.get("aria-hidden", "").lower() == "true" or "hidden" in d:
        return True
    if d.get("role", "").lower() in _DROP_ROLES:
        return True
    toks = set(re.split(r"[\s\-_]+", (d.get("class", "") + " " + d.get("id", "")).lower()))
    # 기본 접힘(.collapse, .show 없음) 영역은 화면에 안 보이는 부속 목록(예: ATT&CK 하위기법 표)
    if "collapse" in toks and "show" not in toks:
        return True
    return bool(toks & _DROP_CLASS_TOKENS)


class _TextExtractor(HTMLParser):
    """블록 단위 텍스트 수집기. 군더더기 영역은 버리고 본문 영역 여부를 함께 기록."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[tuple[str, bool, bool]] = []   # (태그, 버림, 본문영역)
        self.blocks: list[tuple[str, bool]] = []        # (텍스트, 본문영역 안)
        self._buf: list[str] = []
        self.saw_main = False

    def _state(self) -> tuple[bool, bool]:
        # 본문 영역 안이면, 그 바깥 조상(래퍼 div 등)의 버림 판정은 적용하지 않는다 —
        # <div class="site sidebar-left"> 같은 페이지 래퍼 때문에 본문이 통째로 사라지지 않게.
        mains = [i for i, (_, _, m) in enumerate(self.stack) if m]
        scope = self.stack[mains[0]:] if mains else self.stack
        return (any(dropped for _, dropped, _ in scope), bool(mains))

    def _flush(self) -> None:
        text = _WS.sub(" ", "".join(self._buf)).strip()
        self._buf = []
        if text:
            self.blocks.append((text, self._state()[1]))

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in _BLOCK_TAGS or tag == "br":
            self._flush()
        if tag in _VOID_TAGS:
            return
        # 문서 골격·본문 태그는 클래스명만으로 버리지 않는다(<body class="has-navbar"> 등)
        dropped = tag in _DROP_TAGS or (tag not in _NEVER_ATTR_DROP and _drop_by_attrs(attrs))
        is_main = tag in _MAIN_TAGS or dict(attrs).get("role", "") == "main"
        if is_main and not dropped:
            self.saw_main = True
        self.stack.append((tag, dropped, is_main))

    def handle_startendtag(self, tag, attrs):   # <br/>·<svg/> 등 — 열린 영역 없음
        if tag.lower() in _BLOCK_TAGS or tag.lower() == "br":
            self._flush()

    def handle_endtag(self, tag):
        tag = tag.lower()
        for i in range(len(self.stack) - 1, -1, -1):   # 짝 안 맞는 HTML 도 관대하게
            if self.stack[i][0] == tag:
                if tag in _BLOCK_TAGS:
                    self._flush()
                del self.stack[i:]
                return

    def handle_data(self, data):
        if not self._state()[0]:
            self._buf.append(data)

    def text(self) -> str:
        self._flush()
        blocks = [(t, m) for t, m in self.blocks
                  if not (len(t) < 200 and _BOILERPLATE.search(t))
                  and not (len(t) < 800 and _META_LINE.match(t))]
        main = [t for t, m in blocks if m]
        chosen = main if (self.saw_main and main) else [t for t, _ in blocks]
        return _WS.sub(" ", " ".join(chosen)).strip()


def _extract_text_legacy(html_text: str) -> str:
    t = re.sub(r"(?is)<(script|style|head|nav|footer)[^>]*>.*?</\1>", " ", html_text)
    t = _TAG.sub(" ", t)
    t = _html.unescape(t)
    return _WS.sub(" ", t).strip()


def extract_text(html_text: str, limit: int = 600) -> str:
    """HTML 에서 본문 텍스트를 추출한다. 메뉴·헤더·푸터·배너·noscript 등 군더더기
    영역을 버리고, <main>/<article> 본문이 있으면 우선한다. 구조가 망가져 결과가
    비면 기존 방식(태그 제거)으로 되돌아간다."""
    if not html_text:
        return ""
    try:
        ex = _TextExtractor()
        ex.feed(html_text)
        ex.close()
        t = ex.text()
    except Exception:   # noqa: BLE001 — 파서 예외는 기존 방식으로 대체
        t = ""
    if not t:
        t = _extract_text_legacy(html_text)
    return _skip_rfc_header(t)[:limit]


def _skip_rfc_header(t: str) -> str:
    if not _RFC_HEAD.match(t):
        return t
    # 초록은 첫 등장(본문의 'Abstract Syntax' 등 오인 방지). 'Status of this Memo' 는
    # 목차 항목('…… 1' 점 지시선)을 건너뛴 첫 등장 = 실제 절.
    m = _RFC_ABSTRACT.search(t, 0, 3000)
    if not m:
        m = next((x for x in _RFC_STATUS.finditer(t, 0, 6000)
                  if not re.match(r"\s*\.{2,}", t[x.end():])), None)
    if m and t[m.end():].strip():
        return t[m.end():].strip()
    return t


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
        if not key:                       # 빈/공백 주제가 전체를 매칭하는 것 방지
            return []
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


    def learn_all(self) -> list[LearnResult]:
        """지원 주제 전체 **온라인 보강**(선택적). 시작 지식 자체는 저장소에 번들된
        seed-<주제>.md 전수(모든 사용자 동일·오프라인 완비)가 책임지며, 이 메서드는
        그 위에 최신 본문 발췌를 덧씌우는 역할이다. 사용자 Kali 에선 라이브 수집,
        오프라인(egress 차단)이면 출처 포인터만 저장 — 번들 시드가 공백을 메운다."""
        return [self.learn(t) for t in topics()]


# 사용자 제공 자료 수집(ingest). 텍스트/마크다운 + PDF(라이트업 등 실제 포맷).
# 원문은 '사용자 자료'로 보존. P1 재확인: 금지 대상은 '외부' 라이트업의 자동수집일 뿐,
# 사용자가 직접 올린 자료는 참조 허용 — KB 노트로 로드되어 RAG 가 풀이 중 참조한다.
TEXT_EXTS = (".md", ".markdown", ".txt", ".text")
PDF_EXTS = (".pdf",)
INGEST_EXTS = TEXT_EXTS + PDF_EXTS


def _extract_pdf_text(path: str, max_bytes: int) -> str:
    """PDF 텍스트 추출. pdftotext(poppler) 우선, 없으면 pypdf 폴백, 둘 다 없으면 빈 문자열.
    외부 바이너리는 인자로만 경로 전달(인터프리터 로딩 없음)."""
    import shutil
    import subprocess
    exe = shutil.which("pdftotext")
    if exe:
        try:
            r = subprocess.run([exe, "-q", "-enc", "UTF-8", path, "-"],
                               capture_output=True, timeout=120)
            txt = r.stdout.decode("utf-8", "replace")
            if txt.strip():
                return txt[:max_bytes]
        except (OSError, subprocess.SubprocessError):
            pass
    try:                                   # 폴백: 순수 파이썬 라이브러리(있으면)
        import pypdf
        parts, total = [], 0
        for pg in pypdf.PdfReader(path).pages:
            t = pg.extract_text() or ""
            parts.append(t)
            total += len(t)
            if total >= max_bytes:
                break
        return "\n".join(parts)[:max_bytes]
    except Exception:                      # noqa: BLE001 — 라이브러리 미설치/파싱 실패
        return ""


def ingest(src: str, dest_dir: str = "knowledge/notes/ingested",
           max_bytes: int = 200_000) -> list[str]:
    """사용자가 올린 자료(파일 또는 디렉터리)를 지식베이스 노트로 수집한다.
    .md/.txt/.pdf 지원, 파일당 크기 상한, 파일명 새니타이즈. 수집된 노트 경로 목록 반환.
    PDF 는 텍스트 추출(pdftotext/pypdf); 추출 불가(스캔본·도구없음)면 건너뛴다."""
    srcs: list[str] = []
    if os.path.isdir(src):
        for root, _dirs, files in os.walk(src):
            for fn in files:
                if fn.lower().endswith(INGEST_EXTS):
                    srcs.append(os.path.join(root, fn))
    elif os.path.isfile(src) and src.lower().endswith(INGEST_EXTS):
        srcs.append(src)
    out: list[str] = []
    if not srcs:
        return out
    try:
        os.makedirs(dest_dir, exist_ok=True)
    except OSError:
        return out
    for sp in sorted(srcs):
        if sp.lower().endswith(PDF_EXTS):
            content = _extract_pdf_text(sp, max_bytes)
            if not content.strip():        # 추출 실패(스캔 이미지·도구 부재) → 건너뜀
                continue
        else:
            try:
                with open(sp, encoding="utf-8", errors="replace") as f:
                    content = f.read(max_bytes)
            except OSError:
                continue
        safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", os.path.basename(sp)) or "note"
        if not safe.lower().endswith((".md", ".txt", ".markdown", ".text")):
            safe += ".md"
        dp = os.path.join(dest_dir, f"ingested-{safe}")
        if not dp.endswith(".md"):
            dp += ".md"
        header = (f"# 수집 자료: {os.path.basename(sp)}\n\n"
                  "> 사용자 제공 자료 수집(assassin --ingest). 원문 보존 — 사용자가 직접 "
                  "올린 자료로 **참조 허용**(P1 금지 대상은 '외부' 라이트업 자동수집뿐, "
                  "본인 제공 자료는 예외). RAG 가 풀이 중 참조한다.\n\n")
        try:
            with open(dp, "w", encoding="utf-8") as f:
                f.write(header + content)
            out.append(dp)
        except OSError:
            continue
    return out


def topics() -> list[str]:
    return sorted(SOURCES)
