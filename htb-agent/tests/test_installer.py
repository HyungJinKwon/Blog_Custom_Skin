# 실행: htb-agent 디렉토리에서  python3 tests/test_installer.py
# --install-missing: 빠진 도구의 카테고리만 install_tools.sh 로 설치(주입 runner — 실제 apt 미실행).
import sys
sys.path.insert(0, "src")
from htb_agent import installer
from htb_agent.tools import registry

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== 스크립트 경로 ===")
check("install_tools.sh 경로 찾음", installer.script_path() is not None)

print("=== plan: 빠진 도구 → 카테고리 ===")
missing, cats = installer.plan()
check("plan 반환 형식", isinstance(missing, list) and isinstance(cats, list))
check("카테고리는 빠진 도구의 category 들", set(cats) <= {t.category for t in missing} if missing else True)

print("\n=== 모두 설치됨 → 실행 안 함 ===")
# registry.missing_tools 를 '없음'으로 패치
_orig = registry.missing_tools
try:
    registry.missing_tools = lambda categories=None: []
    called = []
    rc, msg = installer.install_missing(runner=lambda a: called.append(a) or 0)
    check("종료코드 0", rc == 0)
    check("설치 스크립트 미실행", not called)
    check("'설치할 것이 없' 안내", "없" in msg)
finally:
    registry.missing_tools = _orig

print("\n=== 빠진 도구 있음 → 해당 카테고리로 스크립트 실행 ===")
fake = [registry.Tool("x", ["xbin"], "web", "테스트"),
        registry.Tool("y", ["ybin"], "smb", "테스트")]
try:
    registry.missing_tools = lambda categories=None: list(fake)
    called = []
    rc, msg = installer.install_missing(runner=lambda a: called.append(a) or 0, use_sudo=False)
    check("runner 1회 호출", len(called) == 1)
    args = called[0]
    check("bash + install_tools.sh 호출", "bash" in args and any("install_tools.sh" in a for a in args))
    check("카테고리 web·smb 전달", "web" in args and "smb" in args)
    check("메시지에 도구명·카테고리", "x" in msg and "web" in msg)
    # 실패 코드 전파
    rc2, _ = installer.install_missing(runner=lambda a: 1, use_sudo=False)
    check("스크립트 실패코드 전파", rc2 == 1)
finally:
    registry.missing_tools = _orig

print("\n=== 특정 카테고리 지정 ===")
try:
    seen = {}
    def mt(categories=None):
        seen["cats"] = categories
        return [registry.Tool("z", ["zbin"], "web", "t")]
    registry.missing_tools = mt
    installer.install_missing(["web"], runner=lambda a: 0, use_sudo=False)
    check("카테고리 필터 전달됨", seen["cats"] == ["web"])
finally:
    registry.missing_tools = _orig

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
