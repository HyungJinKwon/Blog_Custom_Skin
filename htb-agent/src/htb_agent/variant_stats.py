"""
Variant Stats — 실행 결과 기반 옵션 조합(변형) 학습
===================================================

도구별 '옵션 조합 변형(fragment)'이 실제로 쓸만한 결과를 냈는지 성공/시도 횟수로
축적하고, 다음 실행에서 성공률 높은 변형을 먼저 시도하도록 재정렬한다. 세션을
넘겨 누적되도록 JSON 으로 영속화한다(상태 디렉터리). 안전 모델은 불변 — 변형 자체는
여전히 큐레이션된 안전 플래그만, 각 변형도 3관문을 통과한다. 표준 라이브러리만.

점수: 라플라스 평활 (succ+1)/(att+2). 미관측 변형은 0.5(중립)로 취급해
학습된 좋은 변형은 올리고 나쁜 변형은 내리되, 미관측은 원래 순서 근처에 둔다.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field


@dataclass
class VariantStats:
    # key = "binary\x1ffragment" → {"succ": int, "att": int}
    stats: dict = field(default_factory=dict)

    @staticmethod
    def _key(binary: str, fragment: str) -> str:
        return f"{binary}\x1f{fragment}"

    def record(self, binary: str, fragment: str, success: bool) -> None:
        if not binary or not fragment:
            return
        k = self._key(binary, fragment)
        e = self.stats.setdefault(k, {"succ": 0, "att": 0})
        e["att"] += 1
        if success:
            e["succ"] += 1

    def score(self, binary: str, fragment: str) -> float:
        e = self.stats.get(self._key(binary, fragment))
        if not e or e["att"] == 0:
            return 0.5   # 미관측 → 중립
        return (e["succ"] + 1) / (e["att"] + 2)

    def rank(self, binary: str, fragments: list[str]) -> list[str]:
        """성공률 높은 변형이 먼저 오도록 재정렬(동점·미관측은 원래 순서 유지)."""
        indexed = list(enumerate(fragments))
        indexed.sort(key=lambda pair: (-self.score(binary, pair[1]), pair[0]))
        return [f for _, f in indexed]

    # ── 영속화 ──
    def merge(self, other: "VariantStats") -> int:
        """다른 통계를 합산(성장 공유, G1). 키는 binary+fragment 뿐 — 명령 전체·타겟·출력은
        담기지 않아 공유해도 안전. 같은 키는 succ/att 를 더한다. 반환: 병합된 키 수."""
        n = 0
        for k, v in (other.stats or {}).items():
            if not isinstance(v, dict):
                continue
            cur = self.stats.setdefault(k, {"succ": 0, "att": 0})
            cur["succ"] = int(cur.get("succ", 0)) + int(v.get("succ", 0))
            cur["att"] = int(cur.get("att", 0)) + int(v.get("att", 0))
            n += 1
        return n

    def to_dict(self) -> dict:
        return {"stats": self.stats}

    @classmethod
    def from_dict(cls, d: dict) -> "VariantStats":
        return cls(stats=dict((d or {}).get("stats", {})))

    @classmethod
    def load(cls, path: str) -> "VariantStats":
        try:
            with open(path, encoding="utf-8") as f:
                return cls.from_dict(json.load(f))
        except (OSError, ValueError):
            return cls()

    def save(self, path: str) -> None:
        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)
        except OSError:
            pass   # 영속화 실패는 진행을 막지 않는다
