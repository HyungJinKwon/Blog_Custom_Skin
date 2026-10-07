# 실행: htb-agent 디렉토리에서  python3 tests/test_hybrid.py
# 하이브리드 LLM 라우터: 단계별 티어 라우팅 + 상호 폴백.
import sys
sys.path.insert(0, "src")
from htb_agent.llm.base import LLMResponse, Tier, tier_for_phase
from htb_agent.llm.router import LLMRouter, HybridRouter
from htb_agent.llm.fake_provider import FakeProvider
from htb_agent.llm.ollama_provider import OllamaProvider

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

print("\n=== 서킷 브레이커: 연속 오류 백엔드는 세션 동안 건너뜀 ===")
hits = {"n": 0}
def dead(s, u, t):
    hits["n"] += 1
    raise TimeoutError("ollama timeout")
hb = HybridRouter(local=LLMRouter(FakeProvider(dead)),
                  strong=LLMRouter(FakeProvider("id # STRONG")))
for _ in range(5):
    hb.suggest_commands(CTX, "10.0.0.1", tier=Tier.CHEAP)
check("연속 2회 오류 후 로컬 호출 중단(호출 2회)", hits["n"] == 2)
check("차단 사유 기록", "local" in hb.disabled and "TimeoutError" in hb.disabled["local"])
check("오류 2 · 폴백 2 · 강력 응답 5", hb.stats["error"] == 2 and hb.stats["fallback"] == 2
      and hb.stats["strong"] == 5)
check("routing_summary 에 차단 표기", "차단: local(TimeoutError" in hb.routing_summary())

print("\n=== 간헐 오류는 차단하지 않음(성공 시 연속 횟수 초기화) ===")
seq = iter([RuntimeError("x"), "id # LOCAL", RuntimeError("y"), "id # LOCAL"])
def flaky(s, u, t):
    v = next(seq)
    if isinstance(v, Exception):
        raise v
    return v
hf = HybridRouter(local=LLMRouter(FakeProvider(flaky)),
                  strong=LLMRouter(FakeProvider("id # STRONG")))
for _ in range(4):
    hf.suggest_commands(CTX, "10.0.0.1", tier=Tier.CHEAP)
check("오류-성공 반복 → 차단 없음", not hf.disabled and hf.stats["local"] == 2)

print("\n=== 거절(refusal)은 빈 응답과 구분 + 폴백 ===")
refuse = LLMRouter(FakeProvider(lambda s, u, t: LLMResponse("", "m", stop_reason="refusal")))
hr = HybridRouter(local=LLMRouter(FakeProvider("id # LOCAL")), strong=refuse)
r = hr.suggest_commands(CTX, "10.0.0.1", tier=Tier.STRONG)
check("강력 거절 → 로컬 폴백", any("LOCAL" in c for c in r))
check("거절 1 · 빈응답 0 · 폴백 1", hr.stats["refusal"] == 1 and hr.stats["empty"] == 0
      and hr.stats["fallback"] == 1)
he = HybridRouter(local=LLMRouter(FakeProvider("")), strong=None)
check("둘 다 못 하면 미응답 집계", he.suggest_commands(CTX, "10.0.0.1") == []
      and he.stats["empty"] == 1 and he.stats["unserved"] == 1)

print("\n=== analyze 는 강력 우선 + 동일 집계 ===")
ha = HybridRouter(local=LLMRouter(FakeProvider("가설: LOCAL")),
                  strong=LLMRouter(FakeProvider("가설: STRONG")))
check("analyze → 강력", "STRONG" in ha.analyze(CTX, "10.0.0.1") and ha.stats["strong"] == 1)
ha2 = HybridRouter(local=LLMRouter(FakeProvider("가설: LOCAL")),
                   strong=LLMRouter(FakeProvider(boom)))
check("analyze 강력 예외 → 로컬", "LOCAL" in ha2.analyze(CTX, "10.0.0.1"))
check("cost_summary 에 라우팅 집계 포함", "라우팅: 로컬" in h.cost_summary())

print("\n=== Ollama: 미설치 티어 모델은 설치 모델로 대체 ===")
op = OllamaProvider(models={Tier.CHEAP: "llama3.1:8b", Tier.STANDARD: "llama3.1:8b",
                            Tier.STRONG: "llama3.1:70b"})
check("설치 목록 모르면 설정 그대로", op.model_for(Tier.STRONG) == "llama3.1:70b")
op.installed = ["llama3.1:8b"]
check("70b 미설치 → 8b 대체", op.model_for(Tier.STRONG) == "llama3.1:8b")
check("설치된 티어는 그대로", op.model_for(Tier.CHEAP) == "llama3.1:8b")
op.installed = ["qwen2.5:7b"]
check("티어 모델 전부 미설치 → 첫 설치 모델", op.model_for(Tier.STRONG) == "qwen2.5:7b")
op2 = OllamaProvider(models={Tier.STRONG: "mistral"})
op2.installed = ["mistral:latest"]
check(":latest 생략 이름 인식", op2.model_for(Tier.STRONG) == "mistral")

print("\n=== Ollama available(): /api/tags 로 설치 모델 확인 ===")
import io, json as _json
from htb_agent.llm import ollama_provider as _op
_orig = _op.urllib.request.urlopen
def _tags(body):
    class _R(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False
    return lambda url, timeout=3: _R(body)
_op.urllib.request.urlopen = _tags(_json.dumps({"models": [{"name": "llama3.1:8b"}]}).encode())
op3 = OllamaProvider()
ok, _ = op3.available()
check("설치 모델 수집", ok and op3.installed == ["llama3.1:8b"])
_op.urllib.request.urlopen = _tags(b'{"models": []}')
ok, why = OllamaProvider().available()
check("서버는 살아있지만 모델 0개 → 사용 불가 + 안내", not ok and "ollama pull" in why)
_op.urllib.request.urlopen = _tags(b"<html>not json</html>")
ok, _ = OllamaProvider().available()
check("비정상 응답(JSON 아님) → 사용 불가", not ok)
_op.urllib.request.urlopen = _orig

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
