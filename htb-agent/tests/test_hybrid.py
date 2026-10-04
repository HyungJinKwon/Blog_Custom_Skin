# 실행: htb-agent 디렉토리에서  python3 tests/test_hybrid.py
# 하이브리드 LLM 라우터: 단계별 티어 라우팅 + 상호 폴백.
import sys
sys.path.insert(0, "src")
from htb_agent.llm.base import Tier, tier_for_phase
from htb_agent.llm.router import LLMRouter, HybridRouter
from htb_agent.llm.fake_provider import FakeProvider

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

CTX = {"open_ports": ["80/tcp http"], "phase": "열거"}

print("=== 단계 → 티어 매핑 ===")
check("enum=cheap", tier_for_phase("enum") == Tier.CHEAP)
check("access=standard", tier_for_phase("access") == Tier.STANDARD)
check("privesc=strong", tier_for_phase("privesc") == Tier.STRONG)
check("lateral=strong", tier_for_phase("lateral") == Tier.STRONG)
check("미지정=standard", tier_for_phase("") == Tier.STANDARD)

print("\n=== 라우팅: cheap→로컬, strong→강력 ===")
# 프로바이더가 자기 이름을 명령으로 돌려주게 해서 어느 쪽이 쓰였는지 식별
local = LLMRouter(FakeProvider(lambda s, u, t: "nmap -sV 10.0.0.1 # LOCAL"))
strong = LLMRouter(FakeProvider(lambda s, u, t: "nmap -sV 10.0.0.1 # STRONG"))
h = HybridRouter(local=local, strong=strong)
r_cheap = h.suggest_commands(CTX, "10.0.0.1", tier=Tier.CHEAP)
check("cheap → 로컬 사용", any("LOCAL" in c for c in r_cheap))
r_strong = h.suggest_commands(CTX, "10.0.0.1", tier=Tier.STRONG)
check("strong → 강력 사용", any("STRONG" in c for c in r_strong))

print("\n=== 폴백: 우선 백엔드 빈응답 → 보조 ===")
empty_local = LLMRouter(FakeProvider(""))                     # 로컬이 빈 응답
ok_strong = LLMRouter(FakeProvider("curl -I http://10.0.0.1 # STRONG"))
h2 = HybridRouter(local=empty_local, strong=ok_strong)
r = h2.suggest_commands(CTX, "10.0.0.1", tier=Tier.CHEAP)     # cheap=로컬 우선
check("로컬 빈응답 → 강력 폴백", any("STRONG" in c for c in r))

print("\n=== 예외 폴백 ===")
def boom(s, u, t): raise RuntimeError("backend down")
err_local = LLMRouter(FakeProvider(boom))
h3 = HybridRouter(local=err_local, strong=ok_strong)
r3 = h3.suggest_commands(CTX, "10.0.0.1", tier=Tier.CHEAP)
check("로컬 예외 → 강력 폴백", any("STRONG" in c for c in r3))

print("\n=== 단일 백엔드만 있어도 동작 ===")
only_strong = HybridRouter(local=None, strong=ok_strong)
check("로컬 없음 → 강력으로", bool(only_strong.suggest_commands(CTX, "10.0.0.1", tier=Tier.CHEAP)))
only_local = HybridRouter(local=LLMRouter(FakeProvider("id # LOCAL")), strong=None)
check("강력 없음 → 로컬으로", bool(only_local.suggest_commands(CTX, "10.0.0.1", tier=Tier.STRONG)))
try:
    HybridRouter(local=None, strong=None); check("둘다 없음 거부", False)
except ValueError:
    check("둘다 없음 거부", True)

print("\n=== 비용 집계 통합 ===")
check("calls 합산", h.calls == local.calls + strong.calls and h.calls >= 2)
check("cost_summary 양쪽 표기", "로컬(Ollama)" in h.cost_summary() and "강력(Claude)" in h.cost_summary())

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
