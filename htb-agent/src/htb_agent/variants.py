"""
Command Variants — 명령 옵션 조합(경우의 수) 생성
==================================================

한 액션을 하나의 고정 명령으로만 시도하지 않고, 도구별로 **유효하고 안전한 옵션
조합 변형**을 몇 가지 더 만들어 순서대로 시도한다(예: 디렉토리 스캔에 확장자·필터,
nmap 에 타이밍·스크립트). 전부 유한하며(`max_variants` 상한), 각 변형도 실행 전
검증→범위→승인 3관문을 통과한다.

설계 원칙:
  - 큐레이션된 안전한 플래그만 추가(파괴적 옵션 없음). 각 변형은 여전히 동일 타겟.
  - 이미 있는 플래그는 중복 추가하지 않음.
  - 변형은 '추가 시도'일 뿐 — 기본 명령이 항상 첫 번째.
"""

from __future__ import annotations

from .util import binary_of

# 도구별 추가 옵션 조합(각 항목이 하나의 변형을 만든다). 순서 = 우선순위.
_FRAGMENTS: dict[str, list[str]] = {
    "nmap": ["-T4", "-sC", "--version-all", "-A -O"],
    "ffuf": ["-mc all -fc 404", "-e .php,.html,.txt", "-t 50", "-recursion -recursion-depth 1"],
    "gobuster": ["-x php,html,txt", "-t 50", "-s 200,204,301,302,307,401,403"],
    "feroxbuster": ["-x php,html,txt", "-d 2", "-t 50"],
    "curl": ["-L", "-k", "-A 'Mozilla/5.0'", "-s -D -"],
    "nikto": ["-Tuning 1234567890abc", "-ssl"],
    "whatweb": ["-a 3", "-v"],
    "dirb": ["-X .php,.txt,.html"],
    "wfuzz": ["--hc 404"],
    "dnsenum": ["--threads 10"],
    "snmpwalk": ["-v2c -c public", "-v1 -c public"],
}


def expand_variants(command: str, max_variants: int = 1) -> list[str]:
    """
    명령을 [기본] + 옵션 조합 변형들로 확장(최대 max_variants 개).
    max_variants<=1 이면 변형 없이 [기본]만 반환(결정적 기본 동작).
    """
    if max_variants <= 1 or not command.strip():
        return [command]
    base_bin = binary_of(command, strip_path=True)
    frags = _FRAGMENTS.get(base_bin, [])
    existing = set(command.split())
    out = [command]
    for frag in frags:
        if len(out) >= max_variants:
            break
        first_flag = frag.split()[0]
        if first_flag in existing:          # 이미 있는 플래그는 변형 안 함
            continue
        variant = command.rstrip() + " " + frag
        if variant not in out:
            out.append(variant)
    return out
