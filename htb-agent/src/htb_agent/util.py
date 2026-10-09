"""공용 유틸리티."""

from __future__ import annotations

import shlex


def binary_of(command: str, strip_path: bool = False) -> str:
    """
    명령에서 실제 바이너리 토큰을 추출(선행 환경변수 할당 NAME=VALUE 는 건너뜀).
    strip_path=True 면 경로를 제거한 basename 반환.
    """
    try:
        toks = shlex.split(command)
    except ValueError:
        toks = command.split()
    for t in toks:
        if "=" in t and not t.startswith("-"):
            continue
        return t.rsplit("/", 1)[-1] if strip_path else t
    return ""


def network_blocked() -> bool:
    """실제 아웃바운드 네트워크를 전역으로 차단할지(환경변수). 테스트·CI 가 ASSASSIN_NO_NET=1 로
    설정하면 기본 fetcher 들이 실제 요청을 보내지 않는다(주입된 가짜 fetcher 는 영향 없음)."""
    import os
    return os.environ.get("ASSASSIN_NO_NET", "").strip().lower() in ("1", "true", "yes", "on")


def http_get_text(url: str, timeout: int = 10,
                  user_agent: str = "assassin/1.0") -> str | None:
    """urllib 기반 단순 GET → 텍스트(프록시 env 존중). network_blocked()·실패 시 None.
    enrich/learn 등의 기본 fetcher 공용 구현(중복 제거) — 호출부가 allowlist 로 URL 을 거른다."""
    if network_blocked():
        return None
    import urllib.error
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310 (호출부 allowlist)
            return r.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError):
        return None
