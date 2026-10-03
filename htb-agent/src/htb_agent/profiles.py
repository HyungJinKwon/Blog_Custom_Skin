"""
Platform Profiles — HTB / Dreamhack / 일반 CTF 지원
===================================================

에이전트는 원래 HTB 머신(boot2root) 전용이었다. 이 모듈은 **플랫폼 프로파일**로
동작을 매개변수화해 Dreamhack·일반 CTF(Jeopardy) 도 지원한다.

플랫폼별로 달라지는 것:
  - 스코프 모델 : HTB 는 VPN 할당 대역(CIDR)을 코드로 강제. CTF/Dreamhack 은
                  챌린지별 '단일 타겟'(IP/호스트명/포트/URL)을 명시 바인딩(대역 미강제).
  - 플래그 형식 : HTB 는 32-hex(user.txt/root.txt) + HTB{}. Dreamhack 은 DH{},
                  일반 CTF 는 flag{}/FLAG{}/CTF{} 등. (TAG{} 는 공통으로 자동 인식)
  - 플래그 종류 : boot2root(user/root 2개) vs single(챌린지당 1개)
  - 단계/카테고리: boot2root 단계 vs Jeopardy 카테고리(web/pwn/rev/crypto/forensic/misc)

안전 원칙은 플랫폼과 무관하게 동일: 승인제 · 외부 라이트업 미참조 · 명시 범위만.
"""

from __future__ import annotations

from dataclasses import dataclass

# Jeopardy 카테고리(참고/힌트용 라벨)
JEOPARDY_CATEGORIES: list[tuple[str, str]] = [
    ("web", "웹 (Web)"),
    ("pwn", "포너블 (Pwnable)"),
    ("rev", "리버싱 (Reversing)"),
    ("crypto", "암호 (Crypto)"),
    ("forensic", "포렌식 (Forensics)"),
    ("misc", "기타 (Misc)"),
]


@dataclass(frozen=True)
class Platform:
    key: str
    name: str
    banner_subtitle: str
    enforce_ranges: bool          # True=대역(CIDR) 강제(HTB), False=단일 타겟 바인딩(CTF)
    default_ranges: tuple[str, ...] = ()   # enforce_ranges=True 일 때 기본 허용 대역
    flag_prefixes: tuple[str, ...] = ()    # 우선 인식할 TAG{} 접두(예: DH, flag)
    flag_kind: str = "boot2root"           # boot2root(user/root) | single(flag 1개)
    allow_hostname_target: bool = False    # 호스트명 타겟 바인딩 허용(CTF)
    hint: str = ""

    @property
    def is_jeopardy(self) -> bool:
        return self.flag_kind == "single"


PROFILES: dict[str, Platform] = {
    "htb": Platform(
        key="htb",
        name="Hack The Box",
        banner_subtitle="HTB 머신 승인제 풀이 (boot2root)",
        enforce_ranges=True,
        default_ranges=("10.10.10.0/23", "10.129.0.0/16"),
        flag_prefixes=("HTB",),
        flag_kind="boot2root",
        allow_hostname_target=False,
        hint="VPN 할당 머신만. user.txt/root.txt(32-hex) 또는 HTB{} 플래그.",
    ),
    "dreamhack": Platform(
        key="dreamhack",
        name="Dreamhack",
        banner_subtitle="Dreamhack 워게임/CTF 승인제 풀이 (Jeopardy)",
        enforce_ranges=False,
        default_ranges=(),
        flag_prefixes=("DH", "flag", "DREAMHACK"),
        flag_kind="single",
        allow_hostname_target=True,
        hint="챌린지 인스턴스(host:port/URL)만. 플래그는 보통 DH{...}.",
    ),
    "ctf": Platform(
        key="ctf",
        name="일반 CTF",
        banner_subtitle="일반 CTF 승인제 풀이 (Jeopardy)",
        enforce_ranges=False,
        default_ranges=(),
        flag_prefixes=("flag", "FLAG", "CTF"),
        flag_kind="single",
        allow_hostname_target=True,
        hint="대회가 명시한 대상(host:port/URL)만. 플래그는 보통 flag{...}.",
    ),
}


def get_profile(key: str | None) -> Platform:
    """플랫폼 키로 프로파일 조회(기본 htb). 미지원 키는 ValueError."""
    k = (key or "htb").lower()
    if k not in PROFILES:
        raise ValueError(
            f"지원하지 않는 플랫폼: {key!r} (지원: {', '.join(PROFILES)})"
        )
    return PROFILES[k]


def platform_keys() -> list[str]:
    return list(PROFILES)
