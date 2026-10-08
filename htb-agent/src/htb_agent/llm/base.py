"""
LLM Provider 추상화 + 티어링
=============================

백엔드(Claude/Ollama)를 설정으로 교체 가능하게 하는 공통 인터페이스.
티어링으로 작업 난이도에 따라 저렴/표준/고성능 모델을 선택해 비용·토큰을 억제한다.

⚠️ 안전: LLM 출력은 '신뢰하지 않는 데이터'다. 여기서 생성된 어떤 명령도
오케스트레이터의 검증→범위→승인 3관문을 반드시 통과해야 실행된다.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum


class Tier(str, Enum):
    CHEAP = "cheap"        # 루틴 판단(열거 등) — 로컬/저가 모델
    STANDARD = "standard"  # 일반 추론
    STRONG = "strong"      # 어려운 계획/exploit 설계 — 강력 모델


# 모의해킹 단계 → 권장 티어. 하이브리드에서 단계 난이도에 맞춰 백엔드를 고른다.
#   enum(열거)=루틴 → cheap(로컬 Ollama) · access=표준 · privesc/lateral=strong(Claude)
_PHASE_TIER: dict[str, "Tier"] = {}


def tier_for_phase(phase: str) -> "Tier":
    """단계명으로 권장 티어 반환(미지정/미매칭은 STANDARD)."""
    if not _PHASE_TIER:   # 지연 초기화(Enum 정의 후)
        _PHASE_TIER.update({
            "enum": Tier.CHEAP,
            "access": Tier.STANDARD,
            "privesc": Tier.STRONG,
            "lateral": Tier.STRONG,
        })
    return _PHASE_TIER.get((phase or "").lower(), Tier.STANDARD)


@dataclass
class LLMResponse:
    text: str
    model: str
    prompt_tokens: int = 0          # 비캐시 입력 토큰
    completion_tokens: int = 0
    cache_read_tokens: int = 0
    cache_creation_tokens: int = 0
    stop_reason: str = ""           # "refusal" 이면 모델이 응답을 거절(빈 응답과 구분)
    # 네이티브 tool use 응답(지원 백엔드만) — [{"name": str, "input": dict}]. 비면 텍스트 파싱 폴백.
    tool_calls: list = field(default_factory=list)


class LLMProvider(ABC):
    name: str = "base"
    models: dict[Tier, str] = {}

    def model_for(self, tier: Tier) -> str:
        if tier in self.models:
            return self.models[tier]
        return next(iter(self.models.values()), "")

    def available(self) -> tuple[bool, str]:
        """(사용가능?, 사유). 기본 True."""
        return True, "ok"

    @abstractmethod
    def complete(self, system: str, user: str,
                 tier: Tier = Tier.STANDARD, max_tokens: int = 1024,
                 tools: "list | None" = None) -> LLMResponse:
        """tools 가 주어지면(네이티브 tool use 지원 백엔드) 구조화 호출을 시도하고 결과를
        LLMResponse.tool_calls 에 담는다. 미지원 백엔드는 tools 를 무시하고 텍스트로 답한다."""
        ...
