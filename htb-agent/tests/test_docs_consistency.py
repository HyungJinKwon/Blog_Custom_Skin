# 실행: htb-agent 디렉토리에서  python3 tests/test_docs_consistency.py
# 문서 일관성: README·docs 의 'assassin/htb-agent …' 예시에 쓰인 --옵션이 실제 CLI 에 존재하는가.
# (문서 드리프트 방지 — 없는 플래그를 안내하면 초보자가 바로 막힌다)
import glob
import os
import re
import sys
sys.path.insert(0, "src")
from htb_agent.main import build_parser

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)   # htb-agent

VALID = set()
for a in build_parser()._actions:
    for s in a.option_strings:
        if s.startswith("--"):
            VALID.add(s)

print(f"=== 유효 옵션 {len(VALID)}개 로드 ===")
check("옵션 파싱됨", len(VALID) > 20 and "--sandbox" in VALID and "--live-bench" in VALID)

print("\n=== 문서의 assassin 예시 플래그 검증 ===")
cmd_re = re.compile(r"\b(?:assassin|htb-agent)\b(.*)")
flag_re = re.compile(r"(--[a-z][a-z0-9-]*)")
docs = ["README.md"] + sorted(glob.glob("docs/*.md"))
bad = []
checked = 0
for rel in docs:
    path = os.path.join(ROOT, rel)
    if not os.path.isfile(path):
        continue
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            body = line.split("#", 1)[0]          # 주석(설명) 뒤는 제외
            for m in cmd_re.finditer(body):
                for fl in flag_re.findall(m.group(1)):
                    checked += 1
                    if fl not in VALID:
                        bad.append(f"{rel}:{lineno} {fl}")

for b in bad[:30]:
    print("   ✗ " + b)
check(f"검사한 플래그 {checked}개 모두 실제 옵션", not bad)
check("문서 최소 한 곳 이상 assassin 예시 포함", checked > 0)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
