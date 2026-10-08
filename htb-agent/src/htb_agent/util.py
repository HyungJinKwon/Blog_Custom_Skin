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
