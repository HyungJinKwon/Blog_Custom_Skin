"""
Failure Diagnostics — 실행 실패 원인 분류·보고 (사람 판단 보조, 자동 재공격 아님)
================================================================================

실행 결과에서 '무엇이 왜 막혔는가'를 원인별로 분류해 **사람이 읽을 요약**을 만든다.
목적은 세 가지(HackWorld 류 문제의 '보고 측면' 완화)다.

  1. 복구 보조 — 404/403/401/429/5xx·연결거부·타임아웃·DNS·도구부재 등을 구분해,
     사람이 바로 원인을 알고 다음을 판단하게 한다(에이전트가 알아서 재시도하지 않음).
  2. 오판 방지(보고) — 실패를 '대상의 거부(target)'와 '환경/도구/네트워크 문제
     (environment)'로 분리 표기한다. 환경 문제는 '공격 경로가 막혔다'는 근거가
     아님을 사람에게 분명히 보여준다(유효 경로를 섣불리 포기하지 않도록).
  3. 전략 보조 — 흩어진 실패를 범주별로 묶어 한눈에 보여준다.

이 모듈은 **판단 재료만** 만든다. 재시도·경로 변경·포기 결정은 사람이 한다
(승인 3관문은 그대로). 네트워크 호출·상태 변경 없음.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# (범주 키, 사람이 읽을 라벨, 대상의 거부인가?(target) / 환경 문제인가, 조치 힌트)
# is_target=True  → 대상 애플리케이션/서비스가 거부/부재를 응답한 것(경로 판단에 유효).
# is_target=False → 도구·네트워크·실행 환경 문제(공격 경로가 막혔다는 근거 아님).


@dataclass
class FailureDiagnosis:
    category: str          # http-404 / http-403 / timeout / tool-missing ...
    label: str             # 사람이 읽을 한 줄 설명
    is_target: bool        # True=대상의 응답, False=환경/도구/네트워크
    hint: str = ""         # 사람을 위한 다음 조치 힌트(지시가 아니라 참고)

    @property
    def kind(self) -> str:
        return "대상 응답" if self.is_target else "환경/도구"


# HTTP 상태 → 진단. 대상 응답이므로 is_target=True.
_HTTP = {
    401: ("http-401", "인증 필요(401) — 자격 증명이 있어야 접근", True,
          "로그인/기본자격·인증 우회 각도를 사람이 검토"),
    403: ("http-403", "접근 금지(403) — 리소스는 있으나 권한/필터 차단", True,
          "경로/메서드/헤더(X-Forwarded-For 등)·우회 각도를 사람이 검토"),
    404: ("http-404", "없음(404) — 해당 경로/리소스 부재", True,
          "다른 경로·확장자·vhost 를 사람이 검토"),
    429: ("http-429", "요청 과다(429) — 레이트리밋", False,
          "속도를 낮춰 재시도(환경 제약 — 경로 실패 아님)"),
    500: ("http-5xx", "서버 오류(5xx) — 대상 처리 실패", True,
          "입력이 서버 오류를 유발 — 주입 가능성, 사람이 검토"),
}


def _http_status(text: str) -> int | None:
    m = re.search(r"HTTP/\d(?:\.\d)?\s+(\d{3})", text or "")
    if m:
        return int(m.group(1))
    # 요약 포맷("HTTP 200 OK ...")도 인식
    m = re.search(r"\bHTTP\s+(\d{3})\b", text or "")
    return int(m.group(1)) if m else None


# stderr/error 에 나타나는 환경·네트워크 신호(전부 is_target=False).
_ENV_SIGNALS: list[tuple[re.Pattern, str, str, str]] = [
    (re.compile(r"(?i)connection refused"), "conn-refused",
     "연결 거부 — 포트 닫힘/서비스 미기동", "포트 상태를 사람이 재확인(경로 실패 아님)"),
    (re.compile(r"(?i)(connection timed out|timed out|timeout)"), "timeout",
     "타임아웃 — 응답 없음(방화벽·느린 서비스·다운)", "도달성·속도를 사람이 확인(경로 실패 아님)"),
    (re.compile(r"(?i)(could not resolve|name or service not known|no address)"), "dns",
     "이름 해석 실패 — DNS/hosts 미설정", "/etc/hosts 에 도메인 등록을 사람이 확인"),
    (re.compile(r"(?i)(no route to host|network is unreachable)"), "no-route",
     "경로 없음 — 네트워크 도달 불가", "VPN/인터페이스를 사람이 확인(경로 실패 아님)"),
    (re.compile(r"(?i)(ssl|certificate|tls).*(error|verify|unknown)"), "tls",
     "TLS/인증서 문제", "-k/인증서 옵션을 사람이 검토"),
    (re.compile(r"(?i)permission denied"), "perm-denied",
     "권한 거부 — 로컬 실행 권한 부족", "권한/경로를 사람이 확인(대상 거부와 구분)"),
]


def diagnose(cmd: str, out) -> FailureDiagnosis | None:
    """RunOutput 하나를 진단. 성공(출력 있음·오류 없음)이면 None.
    실행 자체가 안 된 경우(launched False)와 실행됐으나 대상이 거부/부재한 경우를 구분."""
    # 1) 실행 자체 실패(바이너리 없음/러너 예외/타임아웃 등) — 환경 문제
    if not getattr(out, "launched", True):
        err = getattr(out, "error", "") or ""
        for pat, cat, label, hint in _ENV_SIGNALS:
            if pat.search(err):
                return FailureDiagnosis(cat, label, False, hint)
        if getattr(out, "timed_out", False):
            return FailureDiagnosis("timeout", "타임아웃 — 응답 없음", False,
                                    "도달성·속도를 사람이 확인(경로 실패 아님)")
        return FailureDiagnosis("launch-failed", f"실행 실패 — {err[:80]}", False,
                                "도구·인자·환경을 사람이 확인(경로 실패 아님)")

    stdout = getattr(out, "stdout", "") or ""
    stderr = getattr(out, "stderr", "") or ""
    blob = stdout + "\n" + stderr

    # 2) 환경/네트워크 신호가 출력에 섞인 경우(실행은 됐으나 네트워크 문제)
    for pat, cat, label, hint in _ENV_SIGNALS:
        if pat.search(stderr) or (not stdout.strip() and pat.search(blob)):
            return FailureDiagnosis(cat, label, False, hint)

    # 3) HTTP 상태 기반 — 대상의 응답
    status = _http_status(blob)
    if status is not None and (status >= 400):
        key = status if status in _HTTP else (500 if status >= 500 else None)
        if key is not None:
            cat, label, is_t, hint = _HTTP[key]
            return FailureDiagnosis(cat, label, is_t, hint)

    # 4) 실행은 됐으나 유의미한 결과가 없음(빈 출력) — 중립(대상/환경 불명)
    if not stdout.strip():
        return FailureDiagnosis("empty-result", "빈 결과 — 유의미한 출력 없음", False,
                                "도구·인자·대상 상태를 사람이 함께 검토")
    return None


# ── 오판 방지 규칙(보고용) ──
# 환경/도구/네트워크 실패만으로는 '공격 경로가 막혔다'고 볼 수 없다. 대상이 서로 다른
# 시도에서 거듭 거부(same target category 2회+)해야 '경로 신빙성 낮음'으로 **표시만** 한다.
def abandonment_signals(diagnoses: list[FailureDiagnosis]) -> dict[str, int]:
    """대상 거부(target) 범주별 횟수 — 2회 이상이면 '사람이 경로 재검토' 후보로 표시.
    환경 문제는 포함하지 않는다(유효 경로를 환경 탓에 포기하지 않도록)."""
    counts: dict[str, int] = {}
    for d in diagnoses:
        if d.is_target:
            counts[d.category] = counts.get(d.category, 0) + 1
    return counts
