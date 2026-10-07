# 실행: htb-agent 디렉토리에서  python3 tests/test_doctor.py
# 초보자 자가진단(--doctor) + 명령 통일/편의.
import io
import os
import sys
from contextlib import redirect_stdout
sys.path.insert(0, "src")
from htb_agent import ui
from htb_agent.doctor import run_doctor
from htb_agent.main import build_parser, main
from htb_agent.tools.runner import FakeRunner, RunOutput
from htb_agent.llm.ollama_provider import OllamaProvider
from htb_agent.llm.base import Tier

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

ui.set_color_enabled(False)

print("=== run_doctor: 섹션·안전 동작 ===")
text, ok = run_doctor()
for sec in ["환경 자가진단", "1. 시스템", "2. 핵심 도구", "3. LLM", "4. 다음 단계"]:
    check(f"섹션: {sec}", sec in text)
check("Python 항목", "Python" in text)
check("LLM 미가용시 규칙기반 안내", "규칙기반으로 완전 동작" in text or "LLM 사용 가능" in text)
check("반환값 bool", isinstance(ok, bool))
check("도구 설치힌트 노출", "install_tools.sh" in text)

print("\n=== --doctor CLI: target 없이 동작 ===")
pp = build_parser()
a = pp.parse_args(["--doctor"])
check("target 선택적", a.target is None and a.doctor is True)
buf = io.StringIO()
with redirect_stdout(buf):
    code = main(["--doctor"])
check("--doctor 종료코드 0/2", code in (0, 2))
check("--doctor 출력에 진단", "환경 자가진단" in buf.getvalue())

print("\n=== target/--doctor 둘 다 없으면 친절한 에러 ===")
err = io.StringIO()
code = None
try:
    import contextlib
    with contextlib.redirect_stderr(err):
        main([])
except SystemExit as e:
    code = e.code
check("인자 없음 → 에러 종료", code not in (0, None))
check("에러에 doctor 안내", "doctor" in err.getvalue())

print("\n=== 정상 실행은 여전히 동작(회귀 가드) ===")
XML = ('<?xml version="1.0"?><nmaprun><host><status state="up"/>'
       '<address addr="10.129.1.5"/><ports>'
       '<port protocol="tcp" portid="22"><state state="open"/>'
       '<service name="ssh"/></port></ports></host></nmaprun>')
r = FakeRunner(lambda c: RunOutput(c, stdout=XML) if c.startswith("nmap")
               else RunOutput(c, stdout="ok"))
buf = io.StringIO()
with redirect_stdout(buf):
    code = main(["10.129.1.5", "--auto", "--no-save", "--no-audit"], runner=r)
check("일반 실행 종료코드 0", code == 0)

print("\n=== OLLAMA_MODEL 환경 오버라이드(하이브리드 편의) ===")
os.environ["OLLAMA_MODEL"] = "qwen2.5:7b"
try:
    prov = OllamaProvider()
    check("전 티어 OLLAMA_MODEL 반영",
          all(prov.model_for(t) == "qwen2.5:7b" for t in Tier))
finally:
    del os.environ["OLLAMA_MODEL"]
check("env 없으면 기본 모델", "llama" in OllamaProvider().model_for(Tier.CHEAP))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
