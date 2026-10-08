"""
Installer — 없는 보안 도구 자동 설치(옵트인, `--install-missing`)
=================================================================

`--doctor` 가 알려 주던 'sudo ./scripts/install_tools.sh' 를 한 명령으로 묶는 편의 기능.
레지스트리에서 **빠진 도구의 카테고리만** 골라 저장소의 공식 설치 스크립트에 넘겨 실행한다
(임의 명령을 만들지 않는다 — 항상 그 스크립트만). 사용자가 명시적으로 실행하는 명령이며,
스크립트 자체가 root 권한을 다시 확인한다.
"""

from __future__ import annotations

import os
import subprocess
from typing import Callable

from .tools import registry


def script_path() -> str | None:
    """저장소의 install_tools.sh 경로(설치본·다른 cwd 에서도 찾음)."""
    cands = [
        os.path.join(os.getcwd(), "scripts", "install_tools.sh"),
        os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..",
                                      "scripts", "install_tools.sh")),
    ]
    for c in cands:
        if os.path.isfile(c):
            return c
    return None


def plan(categories: list[str] | None = None) -> tuple[list, list[str]]:
    """(빠진 도구 목록, 설치할 카테고리 목록). 카테고리는 '빠진 도구가 있는 것'만, 정렬."""
    missing = registry.missing_tools(categories)
    cats = sorted({t.category for t in missing})
    return missing, cats


def install_missing(categories: list[str] | None = None,
                    runner: Callable[..., int] | None = None,
                    use_sudo: bool = True) -> tuple[int, str]:
    """빠진 도구의 카테고리만 install_tools.sh 로 설치. 반환 (종료코드, 사람용 메시지).
    runner: ([args...]) -> returncode (테스트 주입). 없으면 subprocess 로 실제 실행(출력 상속)."""
    missing, cats = plan(categories)
    if not missing:
        return 0, "모든 도구가 이미 설치되어 있습니다 — 설치할 것이 없습니다."
    sp = script_path()
    if sp is None:
        hint = "; ".join(t.install_hint() for t in missing[:3])
        return 2, ("install_tools.sh 를 찾지 못했습니다(저장소 밖에서 실행?). "
                   f"수동 설치: {hint} …")
    args: list[str] = []
    if use_sudo and os.geteuid() != 0:
        args.append("sudo")
    args += ["bash", sp, *cats]
    if runner is None:
        def runner(a: list[str]) -> int:   # 실제 실행 — 출력은 그대로 사용자에게
            try:
                return subprocess.run(a, stdin=subprocess.DEVNULL).returncode
            except (OSError, KeyboardInterrupt) as e:
                print(f"설치 실행 오류: {e}")
                return 1
    rc = runner(args)
    names = ", ".join(t.key for t in missing)
    tail = ("완료 — 'assassin --doctor' 로 재확인하세요." if rc == 0
            else "일부 실패 가능 — 위 로그/‘--doctor’ 확인(개별 설치는 install_hint 참고).")
    return rc, f"빠진 도구 {len(missing)}개({names}) · 카테고리 [{', '.join(cats)}] 설치 시도 — {tail}"
