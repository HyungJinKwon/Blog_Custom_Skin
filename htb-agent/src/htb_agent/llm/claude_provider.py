"""Claude API 백엔드. anthropic SDK + ANTHROPIC_API_KEY 필요(지연 임포트)."""
from __future__ import annotations

import os
from .base import LLMProvider, LLMResponse, Tier


class ClaudeProvider(LLMProvider):
    name = "claude"
    # 티어별 모델 — 비용/성능 균형
    models = {
        Tier.CHEAP: "claude-haiku-4-5-20251001",
        Tier.STANDARD: "claude-sonnet-5-5",
        Tier.STRONG: "claude-opus-5-5",
    }

    def available(self) -> tuple[bool, str]:
        try:
            import anthropic  # noqa: F401
        except ImportError:
            return False, "anthropic SDK 미설치 (pip install anthropic)"
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return False, "ANTHROPIC_API_KEY 환경변수 미설정"
        return True, "ok"

    def complete(self, system: str, user: str,
                 tier: Tier = Tier.STANDARD, max_tokens: int = 1024) -> LLMResponse:
        import anthropic
        client = anthropic.Anthropic()
        model = self.model_for(tier)
        msg = client.messages.create(
            model=model, max_tokens=max_tokens, system=system,
            messages=[{"role": "user", "content": user}],
        )
        text = "".join(getattr(b, "text", "") for b in msg.content
                       if getattr(b, "type", "") == "text")
        usage = getattr(msg, "usage", None)
        return LLMResponse(text, model,
                           getattr(usage, "input_tokens", 0),
                           getattr(usage, "output_tokens", 0))
