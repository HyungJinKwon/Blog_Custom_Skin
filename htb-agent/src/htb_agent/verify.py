"""적대적 재검증(skeptic) — 포착된 플래그의 '신뢰 수준'을 독립 재현 관점에서 재채점한다.

LLM 펜테스트 자동화의 대표 실패모드는 "풀었다고 착각"(false-positive)이다. provenance.py 가
'어디서 나왔나'(공략/로컬/외부)를 분류한다면, 이 모듈은 한 단계 더: **같은 값이 서로 다른
독립 명령에서 재현됐는가**로 확신도를 매긴다(단일 출처는 아직 의심). 판단 재료만 만든다 —
점수를 바꾸거나 플래그를 버리지 않고, 재확인용 '독립 재읽기 명령(문자열)'을 생성할 뿐이다
(생성 전용 — 실행은 3관문을 거친다).

확신도(confidence):
  · reproduced   — 서로 다른 '공략 유래' 명령 ≥2개에서 같은 값 재현(가장 신뢰).
  · single-source — 공략 유래 1개에서만 나옴(참일 가능성 높으나 독립 재확인 권장).
  · untrusted    — 로컬/외부/추론 출처만 있음(공략 아님일 수 있음 — 사람 확인).
  · inconclusive — 형식 불일치/출처 없음(단정 불가 — ARTEX 'inconclusive' 와 동일 태도).

ARTEX 의 retester(별도 세션 재검증, "요청 한 번 실패 ≠ 해결")와 "증거는 하네스가 포착"
원칙을 이 도구의 승인제 파이프라인에 맞춰 클린룸 재구현한 것.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .flag import _FLAG_FMT, _FLAG_HEX
from .util import binary_of

# 확신도 등급(높을수록 신뢰) — 정렬·비교용.
_RANK = {"inconclusive": 0, "untrusted": 1, "single-source": 2, "reproduced": 3}


def flag_format_ok(value: str) -> bool:
    """값이 플래그 형식(32-hex 또는 TAG{...})에 맞는가 — 형식 불일치면 inconclusive 근거."""
    if not value:
        return False
    return bool(_FLAG_FMT.fullmatch(value) or _FLAG_HEX.fullmatch(value))


@dataclass
class Confidence:
    kind: str
    value: str
    level: str = "inconclusive"
    reason: str = ""
    sources: list[str] = field(default_factory=list)   # 공략 유래 '서로 다른' 명령들

    @property
    def rank(self) -> int:
        return _RANK.get(self.level, 0)

    @property
    def label(self) -> str:
        return {
            "reproduced": "재현됨(독립 ≥2 출처 · 신뢰)",
            "single-source": "단일 출처(독립 재확인 권장)",
            "untrusted": "미신뢰(공략 아닐 수 있음 — 사람 확인)",
            "inconclusive": "미확정(형식·출처 불충분 — 단정 불가)",
        }.get(self.level, self.level)


def assess(kind: str, value: str, provenances) -> Confidence:
    """(kind, value) 에 연결된 provenance 들을 모아 확신도를 매긴다. 순수 함수.
    provenances: FlagProvenance 류(`.command`, `.verdict` 속성)의 이터러블."""
    provs = [p for p in provenances
             if getattr(p, "kind", None) == kind and getattr(p, "value", None) == value]
    # 공략 유래 명령을 '정규화된 명령 문자열' 기준 중복 제거해 독립 출처 수를 센다.
    exploit_cmds: list[str] = []
    seen: set[str] = set()
    other = False
    for p in provs:
        v = getattr(p, "verdict", "")
        cmd = (getattr(p, "command", "") or "").strip()
        if v == "exploit-derived":
            key = " ".join(cmd.split())   # 공백 정규화(표시만 다른 같은 명령 합침)
            if key and key not in seen:
                seen.add(key)
                exploit_cmds.append(cmd)
        elif v in ("local-derived", "looked-up", "reasoning-only"):
            other = True
    if not flag_format_ok(value):
        return Confidence(kind, value, "inconclusive",
                          "플래그 형식(32-hex·TAG{}) 불일치 — 단정 불가", exploit_cmds)
    if len(exploit_cmds) >= 2:
        return Confidence(kind, value, "reproduced",
                          f"서로 다른 공략 유래 명령 {len(exploit_cmds)}개에서 재현", exploit_cmds)
    if len(exploit_cmds) == 1:
        return Confidence(kind, value, "single-source",
                          "공략 유래 1개에서만 확인 — 독립 명령으로 재확인 권장", exploit_cmds)
    if other:
        return Confidence(kind, value, "untrusted",
                          "로컬/외부/추론 출처만 있음 — 공략 아닐 수 있음", exploit_cmds)
    return Confidence(kind, value, "inconclusive", "연결된 실행 출처 없음 — 단정 불가", exploit_cmds)


# 같은 파일을 '다른 방법'으로 읽어 교차 확인하기 위한 리더 대체(공백·바이트 노이즈에 강인).
_FLAG_FILES = ("user.txt", "root.txt", "proof.txt", "flag.txt", "local.txt")


def reread_commands(source_command: str) -> list[str]:
    """원래 플래그를 만든 명령과 '다른 방법'으로 같은 산출물을 재읽기하는 명령(문자열)을 만든다.
    생성 전용 — 실행 아님(3관문에서 사람/자동 승인). 재현되면 confidence 를 reproduced 로
    올릴 근거가 된다. 파일 경로를 못 찾으면 빈 목록(억지 추측 안 함)."""
    cmd = source_command or ""
    # 명령에서 플래그 파일 절대/상대 경로 토큰을 뽑는다(user.txt 등으로 끝나는 토큰).
    path = ""
    for tok in cmd.replace("'", " ").replace('"', " ").split():
        low = tok.lower()
        if any(low.endswith(f) or low.endswith(f + ";") for f in _FLAG_FILES):
            path = tok.rstrip(";")
            break
    if not path:
        return []
    orig_bin = binary_of(cmd, strip_path=True)
    # 원래 쓴 리더와 겹치지 않는 대체 리더를 고른다(독립성 확보).
    readers = [("xxd", f"xxd {path} | head"),
               ("od", f"od -c {path} | head"),
               ("sha256sum", f"sha256sum {path}"),
               ("cat", f"cat {path}")]
    out = [c for b, c in readers if b != orig_bin]
    return out[:2]
