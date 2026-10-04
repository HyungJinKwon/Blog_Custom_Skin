# 실행: htb-agent 디렉토리에서  python3 tests/test_platform_llm.py
# LLM 프롬프트 플랫폼 인식화 + Jeopardy 카테고리 배선.
import sys
sys.path.insert(0, "src")
from htb_agent.llm.router import build_system_prompt, LLMRouter
from htb_agent.llm.fake_provider import FakeProvider
from htb_agent.main import build_parser
from htb_agent.profiles import JEOPARDY_CATEGORIES

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== boot2root(HTB) 프롬프트 ===")
b = build_system_prompt({"platform": "Hack The Box", "jeopardy": False}, 5)
check("플랫폼명 반영", "Hack The Box" in b)
check("boot2root 가이드", "boot2root" in b and "user.txt" in b)
check("크리덴셜 리터럴 보존", "{user}/{pass}/{domain}" in b)
check("HTB 하드코딩 제거(훈련용 머신 문구 없음)", "훈련용 머신" not in b)
check("max_items 반영", "최대 5개" in b)

print("\n=== Jeopardy 프롬프트(카테고리별) ===")
w = build_system_prompt({"platform": "Dreamhack", "jeopardy": True,
                         "category": "web", "flag_prefixes": "DH{...}"}, 3)
check("Jeopardy 모드", "Jeopardy" in w)
check("플랫폼명(Dreamhack)", "Dreamhack" in w)
check("웹 카테고리 라벨", "웹" in w)
check("플래그 접두 반영", "DH{...}" in w)
check("pwn 카테고리는 boot2root 와 다름", "boot2root" not in w)
p = build_system_prompt({"platform": "일반 CTF", "jeopardy": True, "category": "pwn"}, 5)
check("pwn 도구 가이드", "pwntools" in p or "gdb" in p)
n = build_system_prompt({"platform": "일반 CTF", "jeopardy": True}, 5)
check("카테고리 미지정 → 관측 추론", "추론" in n)

print("\n=== 라우터가 동적 프롬프트 사용(캡처) ===")
captured = {}
def spy(system, user, tier):
    captured["system"] = system
    return "curl -i http://t/"
r = LLMRouter(FakeProvider(spy))
r.suggest_commands({"platform": "Dreamhack", "jeopardy": True, "category": "crypto"},
                   "chall.dreamhack.io:8080")
check("라우터가 Jeopardy 프롬프트 전달", "Jeopardy" in captured["system"] and "암호" in captured["system"])

print("\n=== --category CLI 플래그 ===")
pp = build_parser()
a = pp.parse_args(["web.chall:8080", "--platform", "ctf", "--category", "web"])
check("--category 파싱", a.category == "web")
check("choices = JEOPARDY_CATEGORIES", set(k for k, _ in JEOPARDY_CATEGORIES) >= {"web", "pwn", "crypto"})
a2 = pp.parse_args(["10.10.10.10"])
check("기본 category None", a2.category is None)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
