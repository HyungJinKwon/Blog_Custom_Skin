"""
LLM Router — 관측·지식을 받아 다음 명령 후보를 추론
====================================================

압축된 관측(OS·포트·서비스)과 지식베이스 제안을 컨텍스트로 LLM 에 넘겨,
'다음에 시도할 명령 후보'를 받는다. 토큰 절감을 위해 원문이 아닌 요약만 넣는다.

반환된 명령은 '후보'일 뿐이다 — 실행 전 반드시 검증→범위→승인 3관문을 거친다.
"""

from __future__ import annotations

import re
from .base import LLMProvider, Tier
from .pricing import estimate_cost


# 플랫폼/모드에 맞춰 동적으로 조립한다(HTB boot2root vs Jeopardy CTF). 리터럴
# {user}/{pass}/{domain} 이 들어가므로 .format() 금지 — replace 로만 치환한다.
_SYSTEM_BASE = """\
당신은 권한이 확인된 {platform} 대상의 침투 테스트/CTF 풀이 보조자다. 주어진
'관측 결과'에만 근거해 다음에 실행할 명령 후보를 제안한다.

규칙(엄수):
- 특정 문제/머신의 공개 라이트업·워크스루를 인용하지 말고, 주어진 관측에서 추론하라.
- 대상은 제공된 타겟 하나뿐이다. 다른 호스트/인터넷 대상 금지.
- 출력은 '명령만' 한 줄에 하나씩. 설명/서론/마크다운/번호매기기 금지.
- 파괴적 명령(rm -rf, mkfs, dd of=/dev/... 등) 금지.
- 크리덴셜이 필요한 명령은 {user}/{pass}/{domain} 플레이스홀더를 그대로 두라.
- 표준 도구를 우선 사용하라.
- 최대 {max_items}개까지만.
{mode_block}"""

# boot2root(HTB) 모드 가이드
_MODE_BOOT2ROOT = """\
- 목표: user.txt → root.txt 획득(boot2root). 열거→초기침투→권한상승 순으로 진행.
- 표준 도구: nmap·ffuf·gobuster·netexec·enum4linux-ng·smbclient·ldapsearch·curl 등."""

# Jeopardy(Dreamhack/CTF) 모드 가이드 — 카테고리별 도구/기법 우선
_MODE_JEOPARDY = """\
- 이것은 Jeopardy 형식 CTF 문제다. 목표는 단일 플래그({prefixes}) 획득.
- 카테고리({category})에 맞는 도구/기법을 우선하라:
  · web   : curl/httpie 요청·ffuf/wfuzz 퍼징·SQLi/XSS/LFI/SSRF·jwt_tool
  · pwn   : file/checksec·gdb/pwndbg·radare2·ROPgadget·pwntools 익스
  · rev   : file·strings·radare2/ghidra 디컴파일·ltrace/strace
  · crypto: 암호 구조 분석·RsaCtfTool·sage/python 수학 공격(무차별 금지 우선 분석)
  · forensic: binwalk/foremost·exiftool·steghide/zsteg·volatility3·wireshark/tshark
- 원격 인스턴스면 nc/curl 로 먼저 상호작용해 거동을 관측하라."""

_CAT_LABELS = {
    "web": "웹", "pwn": "포너블", "rev": "리버싱", "crypto": "암호",
    "forensic": "포렌식", "misc": "기타",
}


def build_system_prompt(context: dict, max_items: int) -> str:
    """관측 컨텍스트(플랫폼/카테고리)에 맞춰 시스템 프롬프트를 조립."""
    platform = context.get("platform") or "Hack The Box"
    if context.get("jeopardy"):
        cat = (context.get("category") or "").lower()
        cat_label = _CAT_LABELS.get(cat, "미상 — 관측으로 추론")
        prefixes = context.get("flag_prefixes") or "flag{...}"
        mode = (_MODE_JEOPARDY
                .replace("{category}", cat_label)
                .replace("{prefixes}", prefixes))
    else:
        mode = _MODE_BOOT2ROOT
    return (_SYSTEM_BASE
            .replace("{platform}", platform)
            .replace("{max_items}", str(max_items))
            .replace("{mode_block}", mode))


class LLMRouter:
    def __init__(self, provider: LLMProvider,
                 default_tier: Tier = Tier.STANDARD, max_items: int = 5):
        self.provider = provider
        self.default_tier = default_tier
        self.max_items = max_items
        # 누적 사용량/비용 집계
        self.calls = 0
        self.total_prompt = 0
        self.total_completion = 0
        self.total_cache_read = 0
        self.total_cost = 0.0

    def cost_summary(self) -> str:
        return (f"LLM 호출 {self.calls}회, 입력 {self.total_prompt} "
                f"(캐시읽기 {self.total_cache_read}) / 출력 {self.total_completion} 토큰, "
                f"추정 비용 ${self.total_cost:.4f}")

    def suggest_commands(self, context: dict, target: str,
                         tier: Tier | None = None,
                         max_items: int | None = None) -> list[str]:
        limit = max_items or self.max_items
        system = build_system_prompt(context, limit)
        user = self._user_prompt(context, target)
        resp = self.provider.complete(system, user, tier or self.default_tier)
        self.calls += 1
        self.total_prompt += resp.prompt_tokens
        self.total_completion += resp.completion_tokens
        self.total_cache_read += resp.cache_read_tokens
        self.total_cost += estimate_cost(resp.model, resp.prompt_tokens,
                                         resp.completion_tokens,
                                         resp.cache_read_tokens,
                                         resp.cache_creation_tokens)
        return self._parse(resp.text, target, limit)

    @staticmethod
    def _user_prompt(context: dict, target: str) -> str:
        lines = [f"타겟: {target}"]
        if context.get("phase"):
            lines.append(f"현재 모의해킹 단계: {context['phase']} — 이 단계에 맞는 명령만 제안하라.")
        if context.get("profile"):
            lines.append(f"OS 판정:\n{context['profile']}")
        if context.get("state"):
            lines.append("현재 상태(월드 모델):\n  " + "\n  ".join(context["state"]))
        if context.get("open_ports"):
            lines.append("열린 포트/서비스:\n  " + "\n  ".join(context["open_ports"]))
        if context.get("findings"):
            lines.append("지금까지 관측(명령 → 결과):\n  " + "\n  ".join(context["findings"]))
        if context.get("kb"):
            lines.append("참고(지식베이스 제안):\n  " + "\n  ".join(context["kb"]))
        if context.get("notes"):
            lines.append("참고(사용자 노트):\n  " + "\n  ".join(context["notes"]))
        lines.append("\n위 관측에 근거해 다음 열거 명령을 제안하라(명령만, 한 줄에 하나).")
        return "\n\n".join(lines)

    @staticmethod
    def _parse(text: str, target: str, limit: int) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for raw in text.splitlines():
            line = raw.strip().strip("`").strip()
            if not line or line.startswith("#") or line.startswith("```"):
                continue
            line = re.sub(r"^\d+[\.\)]\s*", "", line)   # 번호 제거
            line = re.sub(r"^[-*]\s*", "", line)         # 불릿 제거
            line = line.replace("{t}", target)
            # 남은 플레이스홀더(크리덴셜 등)가 있으면 자동실행 후보에서 제외
            if "{" in line and "}" in line:
                continue
            if len(line) > 300 or not re.search(r"[A-Za-z]", line):
                continue
            if line in seen:
                continue
            seen.add(line)
            out.append(line)
            if len(out) >= limit:
                break
        return out


class HybridRouter:
    """
    하이브리드 LLM 라우터 — 로컬(Ollama)과 강력(Claude)을 **단계 난이도로 라우팅**하고
    실패/빈 응답 시 상호 **폴백**한다. 장점 극대화(로컬=무료·토큰절약, Claude=정확)·
    단점 보완(로컬 품질 부족분을 Claude 가, Claude 비용을 로컬이).

      - cheap/standard(열거·일반) → 로컬 우선, 실패 시 강력
      - strong(권한상승·exploit 설계) → 강력 우선, 실패 시 로컬

    LLMRouter 와 동일 인터페이스(suggest_commands·calls·cost_summary)를 제공해
    오케스트레이터가 교체 없이 사용한다.
    """

    def __init__(self, local: "LLMRouter | None" = None,
                 strong: "LLMRouter | None" = None,
                 default_tier: Tier = Tier.STANDARD, max_items: int = 5):
        if local is None and strong is None:
            raise ValueError("HybridRouter: local/strong 중 최소 하나는 필요합니다.")
        self.local = local
        self.strong = strong
        self.default_tier = default_tier
        self.max_items = max_items

    @property
    def calls(self) -> int:
        return (self.local.calls if self.local else 0) + \
               (self.strong.calls if self.strong else 0)

    def _route(self, tier: Tier):
        """(우선, 폴백) 라우터 쌍. 한쪽만 있으면 그걸로."""
        if tier == Tier.STRONG:
            primary, secondary = self.strong, self.local
        else:
            primary, secondary = self.local, self.strong
        primary = primary or secondary
        secondary = secondary if secondary is not primary else None
        return primary, secondary

    def suggest_commands(self, context: dict, target: str,
                         tier: Tier | None = None,
                         max_items: int | None = None) -> list[str]:
        tier = tier or self.default_tier
        primary, secondary = self._route(tier)
        for router in (primary, secondary):
            if router is None:
                continue
            try:
                out = router.suggest_commands(context, target, tier, max_items)
            except Exception:   # 한 백엔드 실패는 폴백으로 흡수
                out = []
            if out:
                return out
        return []

    def cost_summary(self) -> str:
        parts = []
        if self.local:
            parts.append("로컬(Ollama) " + self.local.cost_summary())
        if self.strong:
            parts.append("강력(Claude) " + self.strong.cost_summary())
        return " | ".join(parts)
