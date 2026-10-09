"""발판 성립 검증 (생성 전용) — '진짜 셸이 떴는지'를 출력으로 판정한다.

`_acquire_session` 이 WebRceSession 을 붙여도, 그 엔드포인트에 실제 RCE 가 성립해 있지 않으면
`run("id")` 는 로그인 페이지 HTML·빈 응답을 돌려준다(= 헛발판). 이 모듈은 그 출력을 '파싱'해
셸 생존 신호(uid=·gid=·일반 명령 흔적)가 있는지 판정한다 — 순수 predicate(실행 없음).

사용(실행 라인은 호출측/사용자 — RCE 실행 표면):
    out = session.run("id")              # ← 실제 실행
    if not looks_like_shell(out):        # ← 판정(생성 전용)
        session = None                   # 헛발판 폐기
"""
from __future__ import annotations

import re

# 셸 생존 신호(명령이 실제로 실행된 흔적). id/uname/whoami 등 흔한 출력 패턴.
_LIVE = [
    re.compile(r"uid=\d+\([^)]+\)"),                 # id
    re.compile(r"gid=\d+\([^)]+\)"),                 # id
    re.compile(r"(?im)^(root|www-data|asterisk|daemon|nobody)$"),  # whoami 한 줄
    re.compile(r"(?i)\bLinux\b.+\b(x86_64|GNU/Linux)\b"),          # uname -a
]
# 헛발판 신호(명령 미실행 — 웹 페이지가 그대로 돌아온 경우).
_DEAD = [
    re.compile(r"(?i)<html"),
    re.compile(r"(?i)<!doctype"),
    re.compile(r"(?i)<form"),
    re.compile(r"(?i)freepbx administration"),
    re.compile(r"(?i)login"),
]


def looks_like_shell(output: str) -> bool:
    """출력에 '명령이 실제 실행된 셸 신호'가 있으면 True, 웹페이지/빈 응답이면 False.
    순수 파싱 — 실행하지 않는다. 헛발판(WebRceSession 가 붙었지만 RCE 미성립) 선별용."""
    if not output or not output.strip():
        return False
    if any(p.search(output) for p in _LIVE):
        return True
    # 생존 신호가 없고 명백한 웹 페이지 신호만 있으면 죽은 발판
    if any(p.search(output) for p in _DEAD):
        return False
    # 둘 다 아니면 보수적으로 False(섣부른 '발판 확보' 금지 — 정직성)
    return False


def verify_probe_command() -> str:
    """발판 검증에 쓰는 무해한 프로브 명령(생성 전용 — 문자열). uid 신호를 얻기 위함."""
    return "id; uname -a"
