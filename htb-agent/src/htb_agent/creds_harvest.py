"""
Credential Harvest — 실행 출력에서 평문 자격증명 수확(고신뢰·안전 필터)
========================================================================

관측 출력(설정 덤프·연결 문자열·환경변수 등)에서 **고신뢰 패턴의 평문 자격증명**만
추출한다. 수확된 자격은 월드 모델에 반영되고(권한레벨 credentialed 로 상승 → A1
재진입으로 privesc/lateral 활성화), 셸 메타문자가 없는 '안전한' 값만 실행 볼트에
넣는다(명령 인젝션 차단 — 타겟 출력은 신뢰할 수 없는 데이터). 표준 라이브러리만.

고신뢰 패턴만 사용(노이즈·오탐 최소화):
  - URL 자격: scheme://user:pass@host (ftp/mysql/postgres/mongodb/redis/smb/http…)
  - key=value 쌍: user(name)/password 가 출력에 정확히 1쌍일 때만
"""
from __future__ import annotations

import re

# scheme://user:pass@host
_URL_CRED = re.compile(
    r"[a-z][a-z0-9+.\-]*://([^:/@\s\"']{1,64}):([^@/\s\"']{1,64})@", re.I)
_USER_KV = re.compile(
    r"(?im)\b(?:user(?:name)?|db_user(?:name)?|login|uid)\b[\"']?\s*[:=]\s*"
    r"[\"']?([^\s\"',;]{2,64})")
_PASS_KV = re.compile(
    r"(?im)\b(?:pass(?:word)?|db_pass(?:word)?|passwd|pwd)\b[\"']?\s*[:=]\s*"
    r"[\"']?([^\s\"',;]{2,64})")

# 명백한 플레이스홀더/비밀 아닌 값(오탐 제거)
_PLACEHOLDERS = {
    "password", "passwd", "pass", "null", "none", "example", "changeme",
    "yourpassword", "your_password", "xxxx", "xxxxxxxx", "redacted", "true",
    "false", "secret", "<password>", "...", "******",
}
# 명령에 넣어도 안전한 값(셸 메타문자·공백 없음) — 신뢰불가 출처 인젝션 차단
_UNSAFE = re.compile(r"[\s;&|`$<>(){}\\\"'*?!~\[\]]")


def _ok(val: str) -> bool:
    v = (val or "").strip()
    return bool(v) and v.lower() not in _PLACEHOLDERS


def is_safe_for_cmd(val: str) -> bool:
    """실행 볼트에 넣어도 되는 값인지(셸 인젝션 방지). 월드 표시는 이와 무관하게 허용."""
    return _ok(val) and _UNSAFE.search(val) is None


def harvest(text: str) -> list[tuple[str, str]]:
    """출력에서 (user, pass) 쌍을 고신뢰 패턴으로 추출(중복 제거)."""
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def _add(u: str, p: str) -> None:
        u, p = (u or "").strip(), (p or "").strip()
        if _ok(u) and _ok(p) and (u, p) not in seen:
            seen.add((u, p))
            pairs.append((u, p))

    for m in _URL_CRED.finditer(text or ""):
        _add(m.group(1), m.group(2))
    # key=value 는 '정확히 1쌍'일 때만(여러 개면 짝짓기 모호 → 생략)
    users = [u for u in _USER_KV.findall(text or "") if _ok(u)]
    passes = [p for p in _PASS_KV.findall(text or "") if _ok(p)]
    if len(set(users)) == 1 and len(set(passes)) == 1:
        _add(users[0], passes[0])
    return pairs
