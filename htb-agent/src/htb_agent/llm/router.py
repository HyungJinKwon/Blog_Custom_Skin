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


# 분석가(Analyst) 역할 — 명령 생성과 분리된 '추론' 담당(B3). 관측·상태를 읽고
# 가설·유력 공격경로·다음 집중대상·확신도를 낸다. 이 분석이 명령 생성을 유도한다.
_SYSTEM_ANALYST = """\
당신은 권한이 확인된 {platform} 대상의 침투 테스트/CTF 분석가다. 주어진 '관측
결과'와 '현재 상태(월드 모델)'에만 근거해 상황을 분석한다. 명령을 나열하지 말고,
공격자 관점의 '판단'을 간결하게 제시하라.

규칙(엄수):
- 특정 문제/머신의 공개 라이트업을 인용하지 말고, 주어진 관측에서만 추론하라.
- 확정 사실과 추정을 구분하라(〔확인〕/〔추정〕).
- 과장 금지 — 근거가 약하면 약하다고 하라.

다음 4개 항목으로만, 각 1~3줄로 간결히 답하라(항목 제목 유지):
가설: (관측을 설명하는 가장 유력한 1~2개 가설)
공격경로: (초기침투→권한상승으로 이어질 유력 경로)
다음집중: (지금 가장 가치 높은 열거/검증 대상)
확신도: (상/중/하 + 한 줄 근거)"""


def build_analyst_prompt(context: dict) -> str:
    platform = context.get("platform") or "Hack The Box"
    return _SYSTEM_ANALYST.replace("{platform}", platform)


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
        # 최근 suggest 의 명령별 메타(B4 구조화 출력: 근거·기대신호). cmd -> {rationale,expected}
        self.last_meta: dict[str, dict] = {}
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

    def analyze(self, context: dict, target: str, tier: Tier | None = None) -> str:
        """관측·상태를 읽고 상황 분석(가설·경로·집중·확신도)을 반환(B3 분석가).
        명령 생성과 분리된 추론 단계 — 결과는 후속 명령 생성 컨텍스트로 주입된다."""
        system = build_analyst_prompt(context)
        user = self._analyst_user_prompt(context, target)
        resp = self.provider.complete(system, user, tier or self.default_tier)
        self.calls += 1
        self.total_prompt += resp.prompt_tokens
        self.total_completion += resp.completion_tokens
        self.total_cache_read += resp.cache_read_tokens
        self.total_cost += estimate_cost(resp.model, resp.prompt_tokens,
                                         resp.completion_tokens,
                                         resp.cache_read_tokens,
                                         resp.cache_creation_tokens)
        return resp.text.strip()

    @staticmethod
    def _analyst_user_prompt(context: dict, target: str) -> str:
        lines = [f"타겟: {target}"]
        if context.get("state"):
            lines.append("현재 상태(월드 모델):\n  " + "\n  ".join(context["state"]))
        if context.get("profile"):
            lines.append(f"OS 판정:\n{context['profile']}")
        if context.get("open_ports"):
            lines.append("열린 포트/서비스:\n  " + "\n  ".join(context["open_ports"]))
        if context.get("findings"):
            lines.append("관측(명령→결과):\n  " + "\n  ".join(context["findings"]))
        lines.append("\n위 상황을 분석하라(4개 항목, 간결히).")
        return "\n\n".join(lines)

    @staticmethod
    def _user_prompt(context: dict, target: str) -> str:
        lines = [f"타겟: {target}"]
        if context.get("phase"):
            lines.append(f"현재 모의해킹 단계: {context['phase']} — 이 단계에 맞는 명령만 제안하라.")
        if context.get("profile"):
            lines.append(f"OS 판정:\n{context['profile']}")
        if context.get("state"):
            lines.append("현재 상태(월드 모델):\n  " + "\n  ".join(context["state"]))
        if context.get("analysis"):
            lines.append("분석가 판단(이 판단을 반영해 명령을 고르라):\n" + context["analysis"])
        if context.get("open_ports"):
            lines.append("열린 포트/서비스:\n  " + "\n  ".join(context["open_ports"]))
        if context.get("findings"):
            lines.append("지금까지 관측(명령 → 결과):\n  " + "\n  ".join(context["findings"]))
        if context.get("kb"):
            lines.append("참고(지식베이스 제안):\n  " + "\n  ".join(context["kb"]))
        if context.get("notes"):
            lines.append("참고(사용자 노트):\n  " + "\n  ".join(context["notes"]))
        lines.append(
            "\n위 관측에 근거해 다음 명령을 제안하라. 가능하면 JSON 배열로:\n"
            '[{"command":"<명령>","rationale":"<왜>","expected_signal":"<무엇을 확인>"}]\n'
            "JSON 이 어려우면 명령만 한 줄에 하나씩. 설명/서론 금지.")
        return "\n\n".join(lines)

    @staticmethod
    def _clean_cmd(cmd: str, target: str) -> str:
        """명령 문자열 정리(펜스·불릿·번호 제거, {t} 치환). 부적합하면 ''."""
        line = (cmd or "").strip().strip("`").strip()
        if not line or line.startswith("#") or line.startswith("```"):
            return ""
        line = re.sub(r"^\d+[\.\)]\s*", "", line)   # 번호 제거
        line = re.sub(r"^[-*]\s*", "", line)         # 불릿 제거
        line = line.replace("{t}", target)
        # 남은 플레이스홀더(크리덴셜 등)가 있으면 자동실행 후보에서 제외
        if "{" in line and "}" in line:
            return ""
        if len(line) > 300 or not re.search(r"[A-Za-z]", line):
            return ""
        return line

    def _parse(self, text: str, target: str, limit: int) -> list[str]:
        """B4: JSON 배열(객체/문자열) 우선 파싱(근거·기대신호는 last_meta 로), 실패 시
        기존 라인 기반 폴백. 명령 문자열 리스트를 반환(다운스트림은 그대로)."""
        self.last_meta = {}
        items = self._extract_json(text)
        if items is not None:
            out: list[str] = []
            for it in items:
                if isinstance(it, str):
                    cmd, rat, exp = it, "", ""
                elif isinstance(it, dict):
                    cmd = it.get("command") or it.get("cmd") or ""
                    rat = it.get("rationale") or it.get("why") or ""
                    exp = (it.get("expected_signal") or it.get("expected")
                           or it.get("expect") or "")
                else:
                    continue
                cmd = self._clean_cmd(cmd, target)
                if not cmd or cmd in out:
                    continue
                out.append(cmd)
                if rat or exp:
                    self.last_meta[cmd] = {"rationale": str(rat), "expected": str(exp)}
                if len(out) >= limit:
                    break
            if out:
                return out
        # 폴백: 라인 기반
        out = []
        seen: set[str] = set()
        for raw in text.splitlines():
            line = self._clean_cmd(raw, target)
            if not line or line in seen:
                continue
            seen.add(line)
            out.append(line)
            if len(out) >= limit:
                break
        return out

    @staticmethod
    def _extract_json(text: str):
        """텍스트에서 JSON 배열을 추출(코드펜스 허용). 실패 시 None."""
        import json
        if not text:
            return None
        s = text.strip()
        # ```json ... ``` 펜스 제거
        m = re.search(r"```(?:json)?\s*(.+?)```", s, re.S)
        if m:
            s = m.group(1).strip()
        # 첫 '[' ~ 마지막 ']' 구간만 취함(앞뒤 잡설 허용)
        i, j = s.find("["), s.rfind("]")
        if i == -1 or j == -1 or j < i:
            return None
        try:
            data = json.loads(s[i:j + 1])
        except (ValueError, TypeError):
            return None
        return data if isinstance(data, list) else None


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
        self.last_meta: dict[str, dict] = {}   # 선택된 라우터의 명령별 메타(B4)

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
        self.last_meta = {}
        for router in (primary, secondary):
            if router is None:
                continue
            try:
                out = router.suggest_commands(context, target, tier, max_items)
            except Exception:   # 한 백엔드 실패는 폴백으로 흡수
                out = []
            if out:
                self.last_meta = getattr(router, "last_meta", {})
                return out
        return []

    def analyze(self, context: dict, target: str, tier: Tier | None = None) -> str:
        """분석(B3)은 강력 모델 우선(추론 품질), 실패 시 로컬 폴백."""
        primary, secondary = self._route(Tier.STRONG)
        for router in (primary, secondary):
            if router is None:
                continue
            try:
                out = router.analyze(context, target, tier or Tier.STRONG)
            except Exception:
                out = ""
            if out:
                return out
        return ""

    def cost_summary(self) -> str:
        parts = []
        if self.local:
            parts.append("로컬(Ollama) " + self.local.cost_summary())
        if self.strong:
            parts.append("강력(Claude) " + self.strong.cost_summary())
        return " | ".join(parts)
