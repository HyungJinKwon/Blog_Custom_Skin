# 실행: htb-agent 디렉토리에서  python3 tests/test_tool_use.py
# 네이티브 tool use(구조화 출력) 경로 — 지원 백엔드는 tool_calls 우선, 미지원은 텍스트 폴백.
import sys
sys.path.insert(0, "src")
from htb_agent.llm.base import LLMResponse
from htb_agent.llm.fake_provider import FakeProvider
from htb_agent.llm.router import LLMRouter, build_suggest_tool, _accepts_tools

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

T = "10.129.1.5"

print("=== 스키마 ===")
t = build_suggest_tool(3, with_file=False)
items = t["input_schema"]["properties"]["commands"]
check("이름 propose_commands", t["name"] == "propose_commands")
check("maxItems 반영", items["maxItems"] == 3)
check("file 필드 없음(작업공간 X)", "file" not in items["items"]["properties"])
check("file 필드 있음(작업공간 O)",
      "file" in build_suggest_tool(3, True)["input_schema"]["properties"]["commands"]["items"]["properties"])

print("\n=== 구조화 응답 우선 ===")
tc = [{"name": "propose_commands", "input": {"commands": [
    {"command": "curl -s http://{t}/", "hypothesis": "H1", "expected_signal": "200"},
    {"command": "whatweb {t}"}]}}]
fp = FakeProvider(lambda s, u, tier: LLMResponse(text="", model="fake", tool_calls=tc))
r = LLMRouter(fp)
cmds = r.suggest_commands({}, T)
check("tool_calls 에서 명령 추출", cmds == [f"curl -s http://{T}/", f"whatweb {T}"])
check("structured 표시", r.last_structured is True)
check("메타(가설·기대신호) 보존", r.last_meta[cmds[0]]["hypothesis"] == "H1"
      and r.last_meta[cmds[0]]["expected"] == "200")
check("tools 전달됨", fp.last_tools and fp.last_tools[0]["name"] == "propose_commands")

print("\n=== 텍스트 폴백 ===")
r2 = LLMRouter(FakeProvider('[{"command":"curl -i http://{t}/"}]'))
check("JSON 텍스트 폴백", r2.suggest_commands({}, T) == [f"curl -i http://{T}/"])
check("structured False", r2.last_structured is False)
r3 = LLMRouter(FakeProvider("curl -s http://{t}/robots.txt"))
check("라인 폴백", r3.suggest_commands({}, T) == [f"curl -s http://{T}/robots.txt"])

print("\n=== tools 미지원 프로바이더 호환 ===")
class OldP:
    calls = 0
    def complete(self, system, user, tier=None, max_tokens=1024):
        return LLMResponse(text="nmap -sV {t}", model="old")
check("_accepts_tools False", _accepts_tools(OldP()) is False)
check("구버전 프로바이더도 동작", LLMRouter(OldP()).suggest_commands({}, T) == [f"nmap -sV {T}"])
r4 = LLMRouter(fp); r4.use_tools = False
fp.last_tools = "x"; r4.suggest_commands({}, T)
check("use_tools=False 면 tools 안 보냄", fp.last_tools is None)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
