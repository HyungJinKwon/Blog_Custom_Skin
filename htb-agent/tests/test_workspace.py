# 실행: htb-agent 디렉토리에서  python3 tests/test_workspace.py
import os
import sys
import tempfile
import zipfile

sys.path.insert(0, "src")
from htb_agent.workspace import Workspace, WorkspaceError, sniff

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")


def new_ws():
    d = tempfile.mkdtemp(prefix="ws-test-")
    return Workspace(os.path.join(d, "work"))


print("=== 경로 안전(탈출 거부) ===")
ws = new_ws()
for bad in ["/etc/passwd", "../x", "a/../../b", "", "sub/../../out"]:
    try:
        ws.resolve(bad); check(f"거부: {bad!r}", False)
    except WorkspaceError:
        check(f"거부: {bad!r}", True)
check("정상 상대경로 허용", ws.resolve("exploit.py").endswith("/exploit.py"))
check("/work/ 접두 허용", ws.resolve("/work/a/b.py").endswith("/a/b.py"))

print("\n=== 파일 쓰기 ===")
rel = ws.write_file("solve.py", "#!/usr/bin/env python3\nprint('hi')\n")
check("쓰기 상대경로 반환", rel == "solve.py")
check("written 추적", "solve.py" in ws.written)
full = ws.resolve("solve.py")
check("실행권한(shebang)", os.access(full, os.X_OK))
try:
    ws.write_file("files/x", "nope"); check("files/ 쓰기 거부", False)
except WorkspaceError:
    check("files/ 쓰기 거부", True)
try:
    ws.write_file("big.bin", "A" * (300 * 1024)); check("크기 상한 거부", False)
except WorkspaceError:
    check("크기 상한 거부", True)

print("\n=== 첨부파일 가져오기 ===")
ws = new_ws()
src = tempfile.mkdtemp(prefix="chall-")
with open(os.path.join(src, "app.py"), "w") as f:
    f.write("import os\nFLAG=os.environ['FLAG']\n")
with open(os.path.join(src, "bin"), "wb") as f:
    f.write(b"\x7fELF\x02\x01\x01" + b"\x00" * 60)
added = ws.import_paths([os.path.join(src, "app.py"), os.path.join(src, "bin")])
check("가져온 파일 files/ 아래", all(a.startswith("files/") for a in added))
inv = {fi.path: fi for fi in ws.inventory()}
check("소스 파일 text 판별", inv["files/app.py"].kind == "text")
check("ELF 판별", inv["files/bin"].kind == "elf")
ctx = ws.context_lines()
check("컨텍스트에 소스 본문 발췌", any("import os" in line for line in ctx))
check("컨텍스트에 ELF 본문 미포함", not any("\x7fELF" in line for line in ctx))

print("\n=== zip-slip 방어 ===")
ws = new_ws()
zpath = os.path.join(src, "eggs.zip")
with zipfile.ZipFile(zpath, "w") as z:
    z.writestr("ok.txt", "hello")
    z.writestr("../evil.txt", "pwn")   # 탈출 시도
try:
    ws.import_paths([zpath]); check("zip-slip 항목 거부(예외)", True)  # 거부는 예외로 중단
except WorkspaceError:
    check("zip-slip 항목 거부(예외)", True)
check("탈출 파일이 작업공간 밖에 안 생김",
      not os.path.exists(os.path.join(os.path.dirname(ws.root), "evil.txt")))

print("\n=== sniff ===")
f = os.path.join(src, "t.txt"); open(f, "w").write("plain text")
check("텍스트", sniff(f) == "text")
f2 = os.path.join(src, "z.zip")
with zipfile.ZipFile(f2, "w") as z:
    z.writestr("a", "b")
check("zip 매직", sniff(f2) == "zip")

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
