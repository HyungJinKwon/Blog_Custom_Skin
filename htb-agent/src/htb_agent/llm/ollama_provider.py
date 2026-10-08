"""로컬 Ollama 백엔드 — 오프라인·무과금. 표준 라이브러리만 사용."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .base import LLMProvider, LLMResponse, Tier


class OllamaProvider(LLMProvider):
    name = "ollama"
    models = {
        Tier.CHEAP: "llama3.1:8b",
        Tier.STANDARD: "llama3.1:8b",
        Tier.STRONG: "llama3.1:70b",
    }

    def __init__(self, host: str | None = None, models: dict | None = None):
        self.host = (host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")).rstrip("/")
        self.installed: list[str] = []   # /api/tags 로 확인한 설치 모델(available() 이 채움)
        self.models = dict(self.models)
        # 초보자 편의: OLLAMA_MODEL 하나로 전 티어를 설치된 모델로 덮어쓴다.
        env_model = os.environ.get("OLLAMA_MODEL")
        if env_model:
            self.models = {t: env_model for t in self.models}
        if models:
            self.models = {**self.models, **models}

    def available(self) -> tuple[bool, str]:
        try:
            with urllib.request.urlopen(self.host + "/api/tags", timeout=3) as r:
                data = json.loads(r.read() or b"{}")
        except (urllib.error.URLError, OSError, ValueError) as e:
            return False, f"Ollama 연결 실패({self.host}): {e}"
        self.installed = [m.get("name", "") for m in data.get("models", []) if isinstance(m, dict)]
        if data.get("models") is not None and not self.installed:
            return False, "Ollama 에 설치된 모델 없음(ollama pull llama3.1:8b)"
        return True, "ok"

    def model_for(self, tier: Tier) -> str:
        """티어 모델이 설치돼 있지 않으면 설치된 다른 티어 모델 → 아무 설치 모델 순으로 대체.
        (예: strong=llama3.1:70b 미설치인데 8b 만 있으면 8b 사용 — 없는 모델 호출로 항상 실패하던 문제)"""
        want = super().model_for(tier)
        if not self.installed or self._has(want):
            return want
        for t in (Tier.STANDARD, Tier.CHEAP, Tier.STRONG):
            alt = self.models.get(t, "")
            if alt and self._has(alt):
                return alt
        return self.installed[0]

    def _has(self, name: str) -> bool:
        base = name if ":" in name else name + ":latest"
        return name in self.installed or base in self.installed

    def complete(self, system: str, user: str,
                 tier: Tier = Tier.STANDARD, max_tokens: int = 1024) -> LLMResponse:
        model = self.model_for(tier)
        payload = json.dumps({
            "model": model, "system": system, "prompt": user,
            "stream": False, "options": {"num_predict": max_tokens},
        }).encode()
        req = urllib.request.Request(self.host + "/api/generate", data=payload,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=180) as r:
            data = json.loads(r.read())
        return LLMResponse(data.get("response", ""), model)
