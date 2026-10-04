# 실행: htb-agent 디렉토리에서  python3 tests/test_installer_coverage.py
# 레지스트리(도구 목록)와 install_tools.sh 의 일관성 — 설치 누락 방지(드리프트 가드).
import os
import re
import sys
sys.path.insert(0, "src")
from htb_agent.tools import registry  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

HERE = os.path.dirname(__file__)
installer = open(os.path.join(HERE, "..", "scripts", "install_tools.sh"),
                 encoding="utf-8").read()

print("=== 모든 레지스트리 도구가 설치 스크립트에서 다뤄짐 ===")
uncovered = []
for t in registry.TOOLS:
    tokens = [t.key] + list(t.apt) + list(t.pipx) + list(t.go) + list(t.binaries)
    if not any(re.search(r"\b" + re.escape(tok) + r"\b", installer)
               for tok in tokens if tok):
        uncovered.append(t.key)
check(f"미설치 도구 없음 (발견: {uncovered or '없음'})", not uncovered)

print("\n=== 권한상승 규칙 의존 도구(sshpass) 설치 보장 ===")
check("sshpass apt 설치 포함", "sshpass" in installer)

print("\n=== 설치 스크립트가 쓰는 카테고리가 레지스트리 카테고리를 포함 ===")
reg_cats = {t.category for t in registry.TOOLS}
m = re.search(r"ALL_CATS=\(([^)]*)\)", installer)
sh_cats = set(m.group(1).split()) if m else set()
# wordlist 등 레지스트리 카테고리가 설치 스크립트 ALL_CATS 에 있어야 함
missing_cats = reg_cats - sh_cats
check(f"설치 스크립트가 모든 레지스트리 카테고리 포함 (누락: {missing_cats or '없음'})",
      not missing_cats)

print("\n=== 설치 스크립트 기본 건전성 ===")
check("shebang 존재", installer.startswith("#!/usr/bin/env bash"))
check("root 체크 존재", "need_root" in installer)
check("요약 출력 존재", "요약" in installer)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
