"""
UI — 터미널 출력 렌더링(블루/네이비 팔레트)
=============================================

CLI 출력을 가독성 있게 꾸민다. 색상·박스·구분선·정렬 테이블을 제공하되,
**비-TTY/파이프/NO_COLOR 환경에서는 색을 자동 비활성**(ANSI 미출력)해 로그·테스트가
깨지지 않게 한다. 박스 문자(유니코드)는 색과 무관하게 유지된다.

의존성 없음(표준 라이브러리만). 한글 등 전각 문자는 표시폭 2로 계산해 정렬을 맞춘다.

색상 규칙(§6 블루/네이비 선호):
  accent = 네이비/블루(제목·강조) · info = 시안 · ok = 그린 · warn = 앰버 ·
  err = 레드 · flag = 마젠타 · dim = 회색
"""

from __future__ import annotations

import os
import re
import sys
import unicodedata

# ── ANSI 코드(256색) ────────────────────────────────────────────────
_RESET = "\033[0m"
_CODES = {
    "accent": "38;5;39",    # 밝은 네이비/azure (제목·강조)
    "accent2": "38;5;33",   # 블루 (보조 강조)
    "navy": "38;5;27",      # 진한 네이비
    "info": "38;5;45",      # 시안
    "ok": "38;5;78",        # 그린
    "warn": "38;5;214",     # 앰버
    "err": "38;5;203",      # 레드
    "flag": "38;5;213",     # 마젠타/핑크
    "dim": "38;5;244",      # 회색
    "bold": "1",
}


def _supports_color() -> bool:
    """TTY + 색 지원 여부. NO_COLOR 이면 끄고, FORCE_COLOR 면 켠다."""
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if os.environ.get("TERM", "") == "dumb":
        return False
    try:
        return sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


_ENABLED = _supports_color()


def set_color_enabled(enabled: bool) -> None:
    """색상 강제 on/off(테스트·명시적 제어용)."""
    global _ENABLED
    _ENABLED = bool(enabled)


def color_enabled() -> bool:
    return _ENABLED


def paint(text: str, *styles: str) -> str:
    """지정 스타일로 텍스트를 감싼다(색 비활성 시 원문 그대로)."""
    if not _ENABLED or not styles:
        return text
    seq = ";".join(_CODES[s] for s in styles if s in _CODES)
    if not seq:
        return text
    return f"\033[{seq}m{text}{_RESET}"


# 의미 기반 단축 헬퍼
def accent(t: str) -> str: return paint(t, "accent", "bold")
def accent2(t: str) -> str: return paint(t, "accent2")
def info(t: str) -> str: return paint(t, "info")
def ok(t: str) -> str: return paint(t, "ok")
def warn(t: str) -> str: return paint(t, "warn")
def err(t: str) -> str: return paint(t, "err")
def flag(t: str) -> str: return paint(t, "flag", "bold")
def dim(t: str) -> str: return paint(t, "dim")
def bold(t: str) -> str: return paint(t, "bold")


_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s)


def display_width(s: str) -> int:
    """ANSI 제외 + 전각(한글/CJK) 2폭으로 계산한 표시 폭."""
    text = strip_ansi(s)
    w = 0
    for ch in text:
        if unicodedata.combining(ch):
            continue
        w += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return w


def pad(s: str, width: int, align: str = "left") -> str:
    """표시폭 기준으로 공백 패딩(ANSI·전각 보정)."""
    gap = width - display_width(s)
    if gap <= 0:
        return s
    if align == "right":
        return " " * gap + s
    if align == "center":
        left = gap // 2
        return " " * left + s + " " * (gap - left)
    return s + " " * gap


# ── 레이아웃 요소 ───────────────────────────────────────────────────
_H = "─"
_V = "│"
_TL, _TR, _BL, _BR = "╭", "╮", "╰", "╯"


def rule(title: str = "", width: int = 60, style: str = "accent") -> str:
    """제목이 들어간 수평 구분선. 예: ── 제목 ──────────"""
    if not title:
        return paint(_H * width, style)
    head = _H * 2 + " "
    tail_len = max(1, width - display_width(head) - display_width(title) - 1)
    return (paint(head, style) + paint(title, style, "bold")
            + " " + paint(_H * tail_len, style))


def panel(title: str, lines: list[str], width: int | None = None,
          style: str = "accent") -> str:
    """제목이 달린 둥근 박스. 내부 라인은 표시폭 기준 정렬."""
    body = [str(x) for x in lines]
    inner = max([display_width(title) + 2] + [display_width(b) for b in body]) + 2
    if width is not None:
        inner = max(inner, width - 2)
    top = paint(_TL + _H, style) + paint(f" {title} ", style, "bold") \
        + paint(_H * (inner - display_width(title) - 3) + _TR, style)
    out = [top]
    for b in body:
        out.append(paint(_V, style) + " " + pad(b, inner - 2) + " " + paint(_V, style))
    out.append(paint(_BL + _H * inner + _BR, style))
    return "\n".join(out)


def heading(text: str, icon: str = "") -> str:
    """섹션 헤딩(아이콘 + 강조색 + 하단 가는 선)."""
    label = (f"{icon} " if icon else "") + text
    return paint(label, "accent", "bold")


def kv(key: str, value: str, keywidth: int = 10) -> str:
    """정렬된 key : value 한 줄(key 는 dim, 값은 원색)."""
    return "  " + dim(pad(key, keywidth)) + dim("│ ") + value


def bullet(text: str, marker: str = "·", mstyle: str = "accent2") -> str:
    return "  " + paint(marker, mstyle) + " " + text


# 상태 마커(색 포함)
def mark_ok(t: str = "") -> str: return ok("✔") + ((" " + t) if t else "")
def mark_warn(t: str = "") -> str: return warn("▲") + ((" " + t) if t else "")
def mark_err(t: str = "") -> str: return err("✘") + ((" " + t) if t else "")
def mark_run(t: str = "") -> str: return accent2("▸") + ((" " + t) if t else "")


# ── ASSASSIN 배너 ───────────────────────────────────────────────────
_BANNER_ART = r"""
   ▄▀█ █▀ █▀ ▄▀█ █▀ █▀ █ █▄░█
   █▀█ ▄█ ▄█ █▀█ ▄█ ▄█ █ █░▀█
""".strip("\n")


def banner(subtitle: str = "HTB 머신 승인제 풀이 에이전트") -> str:
    """ASSASSIN 시작 배너(블루/네이비)."""
    art = "\n".join(paint(ln, "accent", "bold") for ln in _BANNER_ART.splitlines())
    tag = "   " + dim("권한 확인된 대상 전용 · 승인제 · 외부 라이트업 미참조")
    sub = "   " + accent2(subtitle)
    return "\n".join([art, sub, tag, rule("", 46, "navy")])
