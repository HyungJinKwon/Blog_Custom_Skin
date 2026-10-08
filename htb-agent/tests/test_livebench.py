# 실행: htb-agent 디렉토리에서  python3 tests/test_livebench.py
# 라이브 벤치: 실제 loopback 서비스 풀이(가능할 때) + docker 타겟 수명주기(주입 exec, 데몬 불필요).
import socket
import sys

sys.path.insert(0, "src")
from htb_agent.knowledge import KnowledgeBase
from htb_agent.livebench import (
    DockerTarget, LiveBenchError, LoopbackTarget, docker_available,
    load_live_suite, run_live_attempt,
)

passed = failed = skipped = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")
def skip(name, why):
    global skipped
    skipped += 1; print(f"  ⏭  {name} — 건너뜀({why})")


def can_bind(ip="127.0.0.11", port=80) -> bool:
    try:
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((ip, port)); s.close(); return True
    except OSError:
        return False


print("=== 문제 로드 ===")
suite = load_live_suite("bench/live")
names = {c.name for c in suite}
check("loopback·docker 문제 로드", {"web-robots-hidden", "web-header-leak",
                                "web-source-comment", "ftp-anon", "redis-key"} <= names)
check("kind 분류", {c.kind for c in suite} == {"loopback", "docker"})
web = next(c for c in suite if c.name == "web-source-comment")
check("flag 접두 파싱 가능", web.flag.startswith("flag{"))

print("\n=== 실제 loopback 풀이(진짜 curl) ===")
import shutil
kb = KnowledgeBase.load()
if not shutil.which("curl"):
    skip("web-source-comment 실제 풀이", "curl 미설치")
elif not can_bind():
    skip("web-source-comment 실제 풀이", "127.0.0.x:80 바인딩 불가(비루트)")
else:
    idx = next(i for i, c in enumerate(suite) if c.name == "web-source-comment")
    r = run_live_attempt(web, 1, idx, kb, max_sweeps=1, max_rounds=1)
    check("실제 서비스에서 플래그 획득", r.solved)
    check("대상 상호작용 유래로 검증(provenance)", r.verified)
    check("명령이 실제로 실행됨", r.executed >= 1)

    # 헤더 유출 문제도(진짜 curl -i)
    hdr = next(c for c in suite if c.name == "web-header-leak")
    hidx = next(i for i, c in enumerate(suite) if c.name == "web-header-leak")
    r2 = run_live_attempt(hdr, 1, hidx, kb, max_sweeps=1, max_rounds=1)
    check("헤더 유출 플래그 획득(검증)", r2.solved and r2.verified)

print("\n=== LoopbackTarget 셋업 실패 처리 ===")
bad = next(c for c in suite if c.name == "web-source-comment")
class _Bad:
    def __init__(self, *a, **k):
        import subprocess as sp
        raise sp.SubprocessError("popen fail")
t = LoopbackTarget(bad, 0, popen=lambda *a, **k: (_ for _ in ()).throw(OSError("no python")))
try:
    t.start(); check("타겟 시작 실패 → 예외", False)
except (LiveBenchError, OSError):
    check("타겟 시작 실패 → 예외", True)

print("\n=== DockerTarget 수명주기(주입 exec, 데몬 불필요) ===")
calls = []
class P:
    def __init__(self, rc=0, out=""):
        self.returncode, self.stdout, self.stderr = rc, out, ""
def dexec(args, **kw):
    calls.append(args)
    j = " ".join(args)
    if "network create" in j:
        return P(0, "netid")
    if args[1] == "build":
        return P(0, "built")
    if args[1] == "run":
        return P(0, "cid")
    if args[1] == "inspect":
        return P(0, "172.20.0.5\n")
    if args[1] == "rm":
        return P(0)
    return P(0)
ftp = next(c for c in suite if c.name == "ftp-anon")
dt = DockerTarget(ftp, exec_fn=dexec)
# _wait_port 는 실제 소켓 — 172.20.0.5 는 떠 있지 않으니 ready_timeout 을 짧게 주고 실패 확인
dt.ch.ready_timeout = 0.5
try:
    dt.start(); started = True
except LiveBenchError:
    started = False
check("build→run→inspect 순서 호출", [a[1] for a in calls[:1]] == ["network"] and
      any(a[1] == "build" for a in calls) and any(a[1] == "run" for a in calls)
      and any(a[1] == "inspect" for a in calls))
check("IP 파싱(172.20.0.5)", dt.address == "172.20.0.5")
check("서비스 미기동 → 준비 실패로 거부", not started)
check("teardown: rm -f 호출", any(a[1] == "rm" for a in calls))

print("\n=== IP 파싱 실패 → 거부 ===")
def dexec_badip(args, **kw):
    j = " ".join(args)
    if args[1] in ("network", "build", "run", "rm"):
        return P(0, "x")
    if args[1] == "inspect":
        return P(0, "not-an-ip\n")
    return P(0)
dt2 = DockerTarget(ftp, exec_fn=dexec_badip)
try:
    dt2.start(); check("잘못된 IP → 예외", False)
except LiveBenchError:
    check("잘못된 IP → 예외", True)

print("\n=== docker_available(주입 exec) ===")
check("데몬 응답 → True", docker_available(exec_fn=lambda *a, **k: P(0, "27.0")))
check("데몬 오류 → False", not docker_available(
    exec_fn=lambda *a, **k: (_ for _ in ()).throw(OSError("down"))))
check("비정상 종료 → False", not docker_available(exec_fn=lambda *a, **k: P(1, "")))

print(f"\n결과: {passed} passed, {failed} failed, {skipped} skipped")
sys.exit(1 if failed else 0)
