# 실행: htb-agent 디렉토리에서  python3 tests/test_llm_errdiag.py
#
# LLM 오류 진단 노출 — API 400 의 핵심 message 가 80자 절단으로 가려지던 문제의 회귀 가드.
# _err_text 가 anthropic body.error.message 를 우선 뽑고, routing_summary 가 차단 전에도
# 최근 오류를 노출하는지 검증.
import sys
sys.path.insert(0, "src")
from htb_agent.llm.router import _err_text, HybridRouter  # noqa: E402
from htb_agent.llm.base import Tier  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")


print("=== _err_text: anthropic body.error.message 우선 ===")
class FakeAPIError(Exception):
    def __init__(self, msg, body):
        super().__init__(msg)
        self.body = body

long_msg = ("max_tokens: 8192 > 4096, the maximum allowed for this model. "
            "이 메시지가 80자 절단되면 원인을 못 본다.")
e = FakeAPIError("Error code: 400 - {...}", {"type": "error",
                 "error": {"type": "invalid_request_error", "message": long_msg}})
check("body.error.message 추출", _err_text(e) == long_msg[:300])
check("80자 넘게 보존(절단 아님)", len(_err_text(e)) > 80)
check("body 없으면 str(e) 폴백", _err_text(Exception("plain error")) == "plain error")
check("limit 로 과하게 길면 자름", len(_err_text(FakeAPIError("x", {"error": {"message": "z" * 999}}))) == 300)


print("\n=== routing_summary: 차단 전에도 최근 오류 노출 ===")
class BoomProvider:
    name = "claude"
    last_stop = ""
    def available(self): return True, "ok"
    def complete(self, system, user, tier=Tier.STANDARD, max_tokens=1024, tools=None):
        raise FakeAPIError("Error code: 400", {"error": {"message": "invalid tool schema XYZ"}})
    def suggest_commands(self, context, target, tier=None, max_items=None):
        return self.complete("", "")   # 오류 전파
    def analyze(self, context, target, tier=None):
        return self.complete("", "")

# strong 만 있는 하이브리드(연속 임계 3) — 1회 실패로는 차단 안 되지만 최근오류는 떠야 함
r = HybridRouter(local=None, strong=BoomProvider(), max_consecutive_errors=3)
r.suggest_commands({}, "10.0.0.1", tier=Tier.STRONG)
summary = r.routing_summary()
check("차단 전이라도 최근오류 노출", "최근오류" in summary and "invalid tool schema XYZ" in summary)
check("아직 차단 아님", "차단:" not in summary)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
