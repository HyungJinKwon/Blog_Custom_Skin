"""Claude API 백엔드. anthropic SDK + ANTHROPIC_API_KEY 필요(지연 임포트)."""
from __future__ import annotations

import os

from .base import LLMProvider, LLMResponse, Tier


class ClaudeProvider(LLMProvider):
    name = "claude"
    # 티어별 모델 — 비용/성능 균형
    models = {
        Tier.CHEAP: "claude-haiku-5-5",
        Tier.STANDARD: "claude-sonnet-5-5",
        Tier.STRONG: "claude-opus-5-5",
    }

    def available(self) -> tuple[bool, str]:
        import importlib.util
        if importlib.util.find_spec("anthropic") is None:
            return False, "anthropic SDK 미설치 (pip install anthropic)"
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return False, "ANTHROPIC_API_KEY 환경변수 미설정"
        return True, "ok"

    def complete(self, system: str, user: str,
                 tier: Tier = Tier.STANDARD, max_tokens: int = 1024,
                 tools: "list | None" = None) -> LLMResponse:
        import anthropic
        client = anthropic.Anthropic()
        model = self.model_for(tier)
        # 큰 시스템 프롬프트는 prefix 캐시 대상(ephemeral) — 반복 호출서 토큰 절감.
        system_blocks = [{"type": "text", "text": system,
                          "cache_control": {"type": "ephemeral"}}]
        kwargs: dict = dict(model=model, max_tokens=max_tokens, system=system_blocks,
                            messages=[{"role": "user", "content": user}])
        if tools:
            # 네이티브 tool use: 첫 도구를 강제 호출 → 응답이 스키마대로 구조화된 JSON 으로 온다
            # (텍스트 파싱 취약성 제거). 결과는 tool_calls 로, 텍스트 폴백은 라우터가 처리.
            kwargs["tools"] = tools
            kwargs["tool_choice"] = {"type": "tool", "name": tools[0]["name"]}
        msg = client.messages.create(**kwargs)
        stop = getattr(msg, "stop_reason", "") or ""
        # 거절(refusal)이면 본문을 쓰지 않는다 — 라우터가 원인을 기록하고 다른 백엔드로 폴백
        text = "" if stop == "refusal" else "".join(
            getattr(b, "text", "") for b in msg.content if getattr(b, "type", "") == "text")
        tool_calls = [] if stop == "refusal" else [
            {"name": getattr(b, "name", ""), "input": getattr(b, "input", {}) or {}}
            for b in msg.content if getattr(b, "type", "") == "tool_use"]
        usage = getattr(msg, "usage", None)
        return LLMResponse(
            text, model, stop_reason=stop, tool_calls=tool_calls,
            prompt_tokens=getattr(usage, "input_tokens", 0) or 0,
            completion_tokens=getattr(usage, "output_tokens", 0) or 0,
            cache_read_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0,
            cache_creation_tokens=getattr(usage, "cache_creation_input_tokens", 0) or 0,
        )
