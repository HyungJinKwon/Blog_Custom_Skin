"""
Autonomous Knowledge Acquisition — 지식 공백 자동 감지·학습 (P1 유지)
======================================================================

에이전트가 풀이 중 **모르는 기술/방법을 만나면 스스로 권위 출처에서 찾아 배운다.**
세 축으로 동작한다.

  1. **별칭 해석(resolve)** — 관측된 실제 제품/서비스(예: mongodb, tomcat, jenkins)를
     번들된 52개 권위 주제(learn.SOURCES)로 매핑한다. "모르는 이름"을 "아는 지식"에
     연결하는 단계.
  2. **온디맨드 학습(acquire)** — 해석된 주제를 권위 출처(허용 도메인)에서 학습해
     지식베이스 노트로 축적하고, **현재 실행 중인 KB 에 즉시 반영**한다(다음 라운드·
     스윕에서 RAG 가 바로 참조). 디스크에도 영속 → 다음 실행에 누적.
  3. **미해석 공백 기록(gap)** — 어떤 주제로도 매핑되지 않는 용어는 **지어내지 않고**
     '미해석 공백'으로 정직하게 기록한다(수동 조사 안내, §3 Zero-Guessing).

안전 설계(기존 모델 유지):
  - 학습은 learn.ReferenceLearner 경유 — **허용 도메인(allowlist) 외 차단**, P1(머신별
    라이트업 미참조) 준수. 가져온 내용은 **신뢰 불가 데이터 → 노트로만 저장, 실행 안 함.**
  - 오프라인(egress 차단)이면 출처 포인터만 — 번들 시드가 이미 보장하므로 공백은
    '기록' 위주로 동작한다.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .learn import SOURCES

# 관측 용어(서비스/제품 이름) → 권위 주제(learn.SOURCES 키) 별칭 매핑.
# 부분일치(substring)로 평가하며, 더 긴 패턴을 먼저 본다(결정성·정확성).
# 전부 번들 시드가 존재하는 52개 주제로만 매핑한다(허용 범위 내).
ALIASES: dict[str, str] = {
    # ── 데이터베이스 ──
    "postgresql": "sqli", "postgres": "sqli", "mariadb": "sqli", "mysql": "sqli",
    "mssql": "sqli", "sql server": "sqli", "oracle": "sqli", "sqlite": "sqli",
    "mongodb": "nosql-injection", "mongo": "nosql-injection", "couchdb": "nosql-injection",
    "cassandra": "nosql-injection", "elasticsearch": "nosql-injection",
    # ── 웹 서버 / 애플리케이션(공개 서비스 익스플로잇) ──
    "apache": "exploit-public-app", "httpd": "exploit-public-app", "nginx": "exploit-public-app",
    "tomcat": "exploit-public-app", "jetty": "exploit-public-app", "jboss": "exploit-public-app",
    "weblogic": "exploit-public-app", "websphere": "exploit-public-app", "iis": "exploit-public-app",
    "wordpress": "exploit-public-app", "drupal": "exploit-public-app", "joomla": "exploit-public-app",
    "magento": "exploit-public-app", "jenkins": "exploit-public-app", "gitlab": "exploit-public-app",
    "jira": "exploit-public-app", "confluence": "exploit-public-app", "grafana": "exploit-public-app",
    "kibana": "exploit-public-app", "phpmyadmin": "exploit-public-app", "struts": "exploit-public-app",
    # ── 웹 기술 → 특정 취약점 주제 ──
    "graphql": "graphql", "jwt": "jwt", "oauth": "oauth", "saml": "authentication",
    "http-proxy": "http", "http": "http", "https": "http", "ssl": "tls", "tls": "tls",
    # ── 인증 / 액티브 디렉터리 ──
    "kerberos": "kerberos", "kpasswd": "kerberos", "krb5": "kerberos",
    "ldap": "ldap", "ldaps": "ldap", "ldapssl": "ldap",
    "microsoft-ds": "smb", "netbios-ssn": "smb", "netbios": "smb", "samba": "smb",
    "cifs": "smb", "smb": "smb", "active directory": "kerberos",
    "winrm": "lateral-movement", "wsman": "lateral-movement",
    "ms-wbt-server": "lateral-movement", "rdp": "lateral-movement", "vnc": "lateral-movement",
    # ── 네트워크 서비스 / 프로토콜 ──
    "openssh": "ssh", "ssh": "ssh",
    "vsftpd": "ftp", "proftpd": "ftp", "pure-ftpd": "ftp", "ftp": "ftp",
    "postfix": "smtp", "sendmail": "smtp", "exim": "smtp", "qmail": "smtp", "smtp": "smtp",
    "snmp": "snmp", "bind": "dns", "named": "dns", "domain": "dns", "dns": "dns",
    "msrpc": "service-discovery", "rpcbind": "service-discovery", "portmapper": "service-discovery",
    "rpc": "service-discovery", "nfs": "service-discovery", "mountd": "service-discovery",
    "telnet": "brute-force", "finger": "service-discovery",
    "redis": "unsecured-credentials", "memcached": "unsecured-credentials",
    "rsync": "service-discovery", "ipmi": "password-cracking",
    # ── AD 공격 체인 / 횡이동 ──
    "bloodhound": "ad-enumeration", "sharphound": "ad-enumeration",
    "ntds": "dcsync", "ntds.dit": "dcsync",
    "chisel": "pivoting", "socat": "pivoting", "proxychains": "pivoting",
    "ligolo": "pivoting", "sshuttle": "pivoting",
    "hashcat": "password-cracking", "john": "password-cracking",
    "mimikatz": "pass-the-ticket", "rubeus": "pass-the-ticket",
    "secretsdump": "dcsync", "lsass": "credential-dumping",
}

# CVE 식별자 — enrich.py(NVD) 경로로 흐르므로 공백 학습 대상에서 제외한다.
_CVE = re.compile(r"(?i)\bCVE-\d{4}-\d{4,}\b")
_TOPICS = set(SOURCES)


@dataclass
class GapOutcome:
    """지식 공백 처리 결과(한 번의 수집 패스)."""
    acquired: list[str] = field(default_factory=list)    # "용어 → 주제 (출처)" 형태
    unresolved: list[str] = field(default_factory=list)  # 매핑 불가(수동 조사 필요) 용어
    notes_added: list[str] = field(default_factory=list)  # KB 에 즉시 주입된 노트 텍스트


def resolve(term: str) -> str | None:
    """관측 용어를 권위 주제(SOURCES 키)로 해석. 직접일치 → 별칭 순. 해석 불가면 None.
    토큰 인식 매칭 — 짧은 별칭(rdp·ssh·ftp…)이 긴 단어 안에서 오탐되지 않도록 한다
    (예: 'weirdproto' 안의 'rdp' 는 매칭 안 됨). 구/하이픈 별칭은 전체 문자열 구절일치,
    평문 별칭은 토큰 정확일치, 긴 별칭(≥5자)만 토큰 내 부분일치 허용(tomcat9 등)."""
    if not term:
        return None
    key = term.strip().lower()
    if not key:
        return None
    if key in _TOPICS:                 # 이미 주제명 그대로
        return key
    tokens = [t for t in re.split(r"[^a-z0-9]+", key) if t]
    tokenset = set(tokens)
    for pat in sorted(ALIASES, key=len, reverse=True):   # 더 긴 패턴 우선
        if " " in pat or "-" in pat:                     # 구/하이픈 → 전체 구절일치
            if pat in key:
                return ALIASES[pat]
        elif pat in tokenset:                            # 평문 → 토큰 정확일치
            return ALIASES[pat]
        elif len(pat) >= 5 and any(pat in tok for tok in tokens):  # 긴 별칭만 부분일치
            return ALIASES[pat]
    return None


def _covered(kb, term: str) -> bool:
    """KB 노트가 이 용어를 이미 다루는지(소문자 포함 여부)."""
    t = term.strip().lower()
    if len(t) < 3:
        return True                    # 너무 짧은 토큰은 공백 판정에서 제외
    return any(t in note.lower() for note in getattr(kb, "notes", []))


def detect(terms: list[str], kb, already: set[str] | None = None
           ) -> tuple[list[tuple[str, str]], list[str]]:
    """관측 용어에서 (학습가능[(용어,주제)], 미해석[용어]) 을 산출.
    - 학습가능: 주제로 해석되며 아직 이번 세션에 수집하지 않은 것(중복 주제 1회).
    - 미해석: 어떤 주제로도 매핑 안 되고 KB 도 다루지 않는 것(지어내지 않고 기록)."""
    already = already or set()
    learnable: list[tuple[str, str]] = []
    unresolved: list[str] = []
    seen_topic: set[str] = set()
    seen_unres: set[str] = set()
    for raw in terms:
        term = (raw or "").strip()
        if not term or _CVE.search(term):   # CVE 는 enrich 경로
            continue
        topic = resolve(term)
        if topic is None:
            low = term.lower()
            if not _covered(kb, term) and low not in seen_unres:
                seen_unres.add(low)
                unresolved.append(term)
            continue
        if topic in already or topic in seen_topic:
            continue
        seen_topic.add(topic)
        learnable.append((term, topic))
    return learnable, unresolved


def _note_text(res) -> str:
    """LearnResult → KB 주입용 노트 텍스트(_load_notes_dir 포맷과 유사)."""
    parts = [f"[자율학습:{res.topic}] 학습 노트: {res.topic} (온디맨드)"]
    for r in res.refs:
        seg = f"{r.title} — {r.url}"
        if r.excerpt:
            seg += f" :: {r.excerpt}"
        parts.append(seg)
    return " ".join(parts)[:500]


def acquire(terms: list[str], kb, learner, already: set[str] | None = None,
            budget: int = 6, web_learner=None) -> GapOutcome:
    """지식 공백을 감지하고, 학습가능 주제를 권위 출처에서 학습해 KB 에 즉시 반영한다.
    - learner: learn.ReferenceLearner (allowlist·P1 가드 내장). None 이면 catalog 학습 생략.
    - web_learner: web_search.WebLearner. 주어지면 '미해석 공백'(카탈로그 밖 용어)을
      인터넷 검색으로 학습한다(HTB 라이트업은 가드로 차단). None 이면 미해석은 기록만.
    - already: 이번 세션에 이미 수집한 주제/용어(중복 방지, 호출측이 갱신).
    - budget: 이번 패스 최대 학습 건수(폭주 방지).
    미해석 공백 중 웹학습으로도 못 채운 것은 지어내지 않고 outcome.unresolved 에 남긴다."""
    out = GapOutcome()
    already = already if already is not None else set()
    learnable, unresolved = detect(terms, kb, already)
    # 1) 카탈로그 매칭 주제 — 권위 출처 학습(기존 경로)
    if learner is not None:
        for term, topic in learnable:
            if len(out.acquired) >= max(0, budget):
                break
            try:
                res = learner.learn(topic)
            except Exception:           # noqa: BLE001 — 학습 실패가 풀이를 막지 않는다
                continue
            already.add(topic)
            if not res.refs:
                continue
            srcs = ", ".join(r.url for r in res.refs[:2])
            out.acquired.append(f"{term} → {topic} ({srcs})")
            if any(r.excerpt for r in res.refs):
                note = _note_text(res)
                kb.notes.append(note)
                out.notes_added.append(note)
    # 2) 미해석 공백(카탈로그 밖) — 인터넷 검색 학습(HTB 라이트업 가드). 남으면 기록만.
    still_unresolved: list[str] = []
    for term in unresolved:
        key = f"web:{term.lower()}"
        if web_learner is None or key in already or len(out.acquired) >= max(0, budget):
            still_unresolved.append(term)
            continue
        already.add(key)
        try:
            wr = web_learner.learn(term)
        except Exception:               # noqa: BLE001
            still_unresolved.append(term)
            continue
        if wr.excerpt and wr.note_path is not None:
            srcs = ", ".join(r.url for r in wr.refs[:2])
            out.acquired.append(f"{term} → (웹) {srcs}")
            note = f"[웹학습:{term}] " + wr.excerpt
            kb.notes.append(note)
            out.notes_added.append(note)
        else:
            still_unresolved.append(term)   # 결과 없음/전부 라이트업 차단 → 기록만
    out.unresolved = still_unresolved
    return out
