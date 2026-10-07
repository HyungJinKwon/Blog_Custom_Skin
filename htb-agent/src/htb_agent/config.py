"""
Config Loader — 파일 기반 설정 (JSON / YAML)
=============================================

CLI/환경변수 외에 설정 파일로 기본값을 관리한다. 우선순위는
**CLI > 설정파일 > 내장 기본값**. 외부 의존성 없이 JSON 을 지원하고,
YAML 은 pyyaml 이 있을 때만(없으면 명확히 안내).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field


class ConfigError(Exception):
    pass


_INT_KEYS = ("max_attempts", "max_enum", "max_llm", "max_rounds", "max_sweeps",
             "max_parallel", "max_variants")
_LIST_KEYS = ("allowed_ranges", "attacker_ips")
_STR_KEYS = ("platform", "knowledge_dir", "knowledge", "state_dir", "llm_backend", "llm_tier")
_KNOWN_KEYS = set(_INT_KEYS) | set(_LIST_KEYS) | set(_STR_KEYS) | {"llm"}
_LLM_KEYS = {"backend", "tier"}
LLM_BACKENDS = ("none", "claude", "ollama", "hybrid")
LLM_TIERS = ("cheap", "standard", "strong")


def _validate(d: dict) -> list[str]:
    """설정 값의 타입·허용값을 검사한다. 오류는 ConfigError, 무해한 문제는 경고 목록.
    (검사 없이 넘기면 문자열 숫자·문자열 대역 등이 실행 중 엉뚱한 예외로 터진다)"""
    warnings = [f"알 수 없는 설정 키(무시됨): {k}" for k in sorted(set(d) - _KNOWN_KEYS)]
    for k in _INT_KEYS:
        v = d.get(k)
        if v is not None and (isinstance(v, bool) or not isinstance(v, int)):
            raise ConfigError(f"'{k}' 는 정수여야 합니다 (받은 값: {v!r})")
    for k in _LIST_KEYS:
        v = d.get(k)
        if v is None:
            continue
        if isinstance(v, str):
            d[k] = [v]          # 단일 값 편의 허용 — 문자열을 글자 단위로 쪼개지 않도록
        elif not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            raise ConfigError(f"'{k}' 는 문자열 목록이어야 합니다 (받은 값: {v!r})")
    for k in _STR_KEYS:
        v = d.get(k)
        if v is not None and not isinstance(v, str):
            raise ConfigError(f"'{k}' 는 문자열이어야 합니다 (받은 값: {v!r})")
    llm = d.get("llm")
    if llm is not None:
        if not isinstance(llm, dict):
            raise ConfigError(f"'llm' 은 매핑이어야 합니다 (받은 값: {llm!r})")
        warnings += [f"알 수 없는 설정 키(무시됨): llm.{k}" for k in sorted(set(llm) - _LLM_KEYS)]
    llm = llm or {}
    backend = llm.get("backend", d.get("llm_backend"))
    tier = llm.get("tier", d.get("llm_tier"))
    if backend is not None and backend not in LLM_BACKENDS:
        raise ConfigError(f"지원하지 않는 llm backend: {backend!r} (지원: {', '.join(LLM_BACKENDS)})")
    if tier is not None and tier not in LLM_TIERS:
        raise ConfigError(f"지원하지 않는 llm tier: {tier!r} (지원: {', '.join(LLM_TIERS)})")
    return warnings


@dataclass
class Config:
    allowed_ranges: list[str] | None = None
    attacker_ips: list[str] | None = None
    platform: str | None = None
    llm_backend: str | None = None
    llm_tier: str | None = None
    max_attempts: int | None = None
    max_enum: int | None = None
    max_llm: int | None = None
    max_rounds: int | None = None
    max_sweeps: int | None = None
    max_parallel: int | None = None
    max_variants: int | None = None
    knowledge_dir: str | None = None
    state_dir: str | None = None
    warnings: list[str] = field(default_factory=list)   # 무해한 문제(알 수 없는 키 등)

    @classmethod
    def from_dict(cls, d: dict) -> "Config":
        d = dict(d or {})
        warnings = _validate(d)
        llm = d.get("llm", {}) or {}
        return cls(
            warnings=warnings,
            allowed_ranges=d.get("allowed_ranges"),
            attacker_ips=d.get("attacker_ips"),
            platform=d.get("platform"),
            llm_backend=llm.get("backend", d.get("llm_backend")),
            llm_tier=llm.get("tier", d.get("llm_tier")),
            max_attempts=d.get("max_attempts"),
            max_enum=d.get("max_enum"),
            max_llm=d.get("max_llm"),
            max_rounds=d.get("max_rounds"),
            max_sweeps=d.get("max_sweeps"),
            max_parallel=d.get("max_parallel"),
            max_variants=d.get("max_variants"),
            knowledge_dir=d.get("knowledge_dir", d.get("knowledge")),
            state_dir=d.get("state_dir"),
        )


def _read_file(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        raise ConfigError(f"설정 파일을 열 수 없음: {path} ({e})") from e
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml  # type: ignore
        except ImportError as e:
            raise ConfigError(
                "YAML 설정은 pyyaml 필요 — 'pip install pyyaml' 하거나 JSON(.json) 사용"
            ) from e
        try:
            return yaml.safe_load(text) or {}
        except yaml.YAMLError as e:  # type: ignore
            raise ConfigError(f"YAML 파싱 실패: {e}") from e
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise ConfigError(f"JSON 파싱 실패: {e}") from e


def load_config(path: str) -> Config:
    data = _read_file(path)
    if not isinstance(data, dict):
        raise ConfigError("설정 최상위는 매핑(객체)이어야 합니다.")
    return Config.from_dict(data)


def pick(cli_value, config_value, default):
    """우선순위 해소: CLI(None 아님) > config(None 아님) > 기본값."""
    if cli_value is not None:
        return cli_value
    if config_value is not None:
        return config_value
    return default
