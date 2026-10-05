"""
해시 크래킹 자동 준비 — John the Ripper / hashcat 명령 생성 (권한 확인 자산 전용)
==============================================================================

캡처한 해시(Kerberoast/AS-REP/NetNTLMv2/유닉스 crypt/NT 등)의 **종류를 식별**하고
john·hashcat 크래킹 명령(올바른 모드/포맷·워드리스트)을 '자동 생성'한다. 크래킹은
무겁고 워드리스트·GPU 가 필요해 에이전트는 **실행하지 않고 준비만** 한다(생성 전용
안전 경계). 식별은 패턴 기반 best-effort — 모호하면 후보를 여러 개 제시한다.
전부 표준 라이브러리만.

흐름:
  해시 문자열 → identify(종류·hashcat 모드·john 포맷) → commands(john/hashcat 명령)
  오케스트레이터는 enum/LLM 출력·크리덴셜 볼트에서 scan_hashes 로 해시를 자동 수집.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"
DEFAULT_HASHFILE = "hash.txt"


@dataclass
class HashGuess:
    name: str
    hashcat_mode: str = ""   # -m 값 (없으면 "")
    john_format: str = ""    # --format= 값 (없으면 "")


@dataclass
class CrackCmd:
    tool: str      # hashcat / john
    name: str
    command: str


@dataclass
class CrackJob:
    hash: str
    guesses: list[HashGuess] = field(default_factory=list)
    commands: list[CrackCmd] = field(default_factory=list)


_HEX = "0123456789abcdefABCDEF"


def _is_hex(s: str, n: int) -> bool:
    return len(s) == n and all(c in _HEX for c in s)


def identify(h: str) -> list[HashGuess]:
    """해시 문자열의 종류 후보를 반환(접두 우선, 그다음 길이/형식)."""
    h = (h or "").strip()
    if not h:
        return []
    low = h.lower()

    # ── 접두(prefix) 기반 — 고신뢰 ──
    if low.startswith("$krb5tgs$"):
        m = re.match(r"\$krb5tgs\$(\d+)\$", low)
        et = m.group(1) if m else "23"
        mode = {"23": "13100", "17": "19600", "18": "19700"}.get(et, "13100")
        return [HashGuess(f"Kerberoast TGS-REP (etype {et})", mode, "krb5tgs")]
    if low.startswith("$krb5asrep$"):
        return [HashGuess("AS-REP Roast", "18200", "krb5asrep")]
    if low.startswith("$krb5pa$") or low.startswith("$krb5tgs$18$"):
        return [HashGuess("Kerberos (AES)", "19700", "krb5tgs")]
    if low.startswith("$1$"):
        return [HashGuess("md5crypt (Unix $1$)", "500", "md5crypt")]
    if low.startswith("$5$"):
        return [HashGuess("sha256crypt (Unix $5$)", "7400", "sha256crypt")]
    if low.startswith("$6$"):
        return [HashGuess("sha512crypt (Unix $6$)", "1800", "sha512crypt")]
    if low.startswith(("$2a$", "$2b$", "$2y$")):
        return [HashGuess("bcrypt ($2*$)", "3200", "bcrypt")]
    if low.startswith("$y$") or low.startswith("$7$"):
        return [HashGuess("yescrypt/scrypt (Unix)", "", "")]
    if low.startswith("{ssha}") or low.startswith("$apr1$"):
        return [HashGuess("apr1/SSHA (web/LDAP)", "1600", "md5crypt-long")]
    # NetNTLMv2: user::DOMAIN:serverchal:...:... (콜론 다수)
    if re.match(r"^[^:]+::[^:]*:[0-9a-fA-F]{16}:[0-9a-fA-F]{32}:", h):
        return [HashGuess("NetNTLMv2", "5600", "netntlmv2")]
    # MySQL4.1+ : '*' + 40 hex
    if h.startswith("*") and _is_hex(h[1:], 40):
        return [HashGuess("MySQL4.1+ SHA1", "300", "mysql-sha1")]

    # ── 길이 기반(원시 해시) — 모호하면 후보 병기 ──
    if _is_hex(h, 32):
        return [HashGuess("NTLM (NT 해시)", "1000", "nt"),
                HashGuess("raw MD5", "0", "raw-md5")]
    if _is_hex(h, 40):
        return [HashGuess("raw SHA1", "100", "raw-sha1")]
    if _is_hex(h, 64):
        return [HashGuess("raw SHA256", "1400", "raw-sha256")]
    if _is_hex(h, 128):
        return [HashGuess("raw SHA512", "1700", "raw-sha512")]
    return [HashGuess("미상(식별 실패) — hashid/hash-identifier 로 수동 확인", "", "")]


# 오케스트레이터 자동수집용: 출력/텍스트에서 고신뢰 해시만 추출(원시 hex 는 노이즈라 제외)
_SCAN_PATTERNS = [
    re.compile(r"\$krb5tgs\$\d+\$[^\s'\"]+"),
    re.compile(r"\$krb5asrep\$\d+\$[^\s'\"]+"),
    re.compile(r"[^\s:'\"]+::[^\s:'\"]*:[0-9a-fA-F]{16}:[0-9a-fA-F]{32}:[0-9a-fA-F]+"),
    re.compile(r"\$(?:1|5|6)\$[^\s'\"]+"),
    re.compile(r"\$2[aby]\$[^\s'\"]+"),
]


def scan_hashes(text: str, limit: int = 20) -> list[str]:
    """텍스트에서 크래킹 대상 해시(고신뢰 패턴)를 중복 없이 추출."""
    out: list[str] = []
    for pat in _SCAN_PATTERNS:
        for mm in pat.findall(text or ""):
            cand = mm.strip().strip("'\"")
            if cand and cand not in out:
                out.append(cand)
                if len(out) >= limit:
                    return out
    return out


def commands(h: str, hashfile: str = DEFAULT_HASHFILE,
             wordlist: str = DEFAULT_WORDLIST) -> list[CrackCmd]:
    """해시 종류별 john·hashcat 명령 생성(생성 전용 — 실행 안 함)."""
    out: list[CrackCmd] = []
    seen: set[str] = set()
    for g in identify(h):
        if g.hashcat_mode:
            c = f"hashcat -m {g.hashcat_mode} {hashfile} {wordlist}"
            if c not in seen:
                seen.add(c)
                out.append(CrackCmd("hashcat", g.name, c))
        if g.john_format:
            c = f"john --format={g.john_format} --wordlist={wordlist} {hashfile}"
            if c not in seen:
                seen.add(c)
                out.append(CrackCmd("john", g.name, c))
    # 포맷 자동판별 john 폴백(식별 실패 대비)
    fb = f"john --wordlist={wordlist} {hashfile}"
    if fb not in seen:
        out.append(CrackCmd("john", "자동판별(폴백)", fb))
    return out


def prepare(hashes: list[str], wordlist: str = DEFAULT_WORDLIST,
            hashfile: str = DEFAULT_HASHFILE) -> list[CrackJob]:
    """여러 해시에 대한 크래킹 작업(식별+명령)을 생성(생성 전용)."""
    jobs: list[CrackJob] = []
    seen: set[str] = set()
    for h in hashes:
        h = (h or "").strip()
        if not h or h in seen:
            continue
        seen.add(h)
        jobs.append(CrackJob(hash=h, guesses=identify(h),
                             commands=commands(h, hashfile, wordlist)))
    return jobs


def render(h: str, wordlist: str = DEFAULT_WORDLIST) -> str:
    """사람이 보는 텍스트(블루/네이비 UI). 생성 전용 — 실행하지 않음."""
    from . import ui
    out = [ui.banner("해시 크래킹 자동 준비 (권한 확인 자산 전용)")]
    guesses = identify(h)
    if not guesses:
        out.append(ui.dim("해시가 비었습니다 — 'assassin --crack <HASH>' 형식으로 지정."))
        return "\n".join(out)
    out.append(ui.dim(f"대상 해시: {h[:72]}{'…' if len(h) > 72 else ''}\n"
                      "생성만 함(에이전트는 실행 안 함 — 크래킹은 사용자 환경에서).\n"))
    out.append(ui.panel("식별 결과(후보)", [
        ui.bullet(f"{g.name}"
                  + (f"  · hashcat -m {g.hashcat_mode}" if g.hashcat_mode else "")
                  + (f"  · john --format={g.john_format}" if g.john_format else ""),
                  "▸", "accent2") for g in guesses], style="navy"))
    out.append(ui.rule("크래킹 명령"))
    for c in commands(h, wordlist=wordlist):
        out.append(ui.accent2(f"[{c.tool} · {c.name}]"))
        out.append("  " + c.command)
    out.append(ui.rule())
    out.append(ui.dim("\n워드리스트 예: rockyou.txt · 규칙 추가 예: hashcat ... -r "
                      "/usr/share/hashcat/rules/best64.rule"))
    out.append(ui.dim("권한이 확인된 자산의 해시만 크래킹하세요. 출처: hashcat/john 공식 문서."))
    return "\n".join(out)
