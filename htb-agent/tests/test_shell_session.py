# 실행: htb-agent 디렉토리에서  python3 tests/test_shell_session.py
#
# B단계 — 발판 셸 세션 추상화. 소켓 I/O 없이(생성 전용) 상태관리·리스너/페이로드 생성·
# 명령 프레이밍/마커 파싱을 검증. 실제 송수신은 주입 콜러블(사용자) 몫.
import sys
sys.path.insert(0, "src")
from htb_agent.shell_session import (                               # noqa: E402
    CommandRunnerSession, ReverseShellSession, ShellSession, ShellState,
    WebRceSession, frame_command, strip_marker)

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

def _raises(fn, exc=Exception):
    try:
        fn(); return False
    except exc:
        return True

print("=== ShellSession ABC ===")
try:
    ShellSession()  # type: ignore[abstract]
    check("ABC 직접 인스턴스화 불가", False)
except TypeError:
    check("ABC 직접 인스턴스화 불가", True)

print("\n=== CommandRunnerSession (SSH one-shot 어댑터) ===")
calls = []
def fake_run(c):
    calls.append(c)
    return f"[out of] {c}"
sess = CommandRunnerSession(fake_run, wrap=lambda c: f"sshpass ssh user@h {c!r}", label="ssh")
out = sess.run("id")
check("wrap 적용 후 run_fn 실행", calls and calls[0].startswith("sshpass ssh user@h"))
check("원래 명령이 wrap 안에 포함", "'id'" in calls[0])
check("출력 반환", "[out of]" in out)
check("alive True", sess.alive is True)
sess.close()
check("close 후 alive False", sess.alive is False)
try:
    sess.run("x"); check("종료 후 run 거부", False)
except RuntimeError:
    check("종료 후 run 거부", True)

print("\n=== frame_command / strip_marker ===")
framed = frame_command("whoami", "__M_")
check("프레이밍에 완료 마커+종료코드", framed == "whoami; echo __M_$?")
body, rc = strip_marker("root\n__M_0\n", "__M_")
check("본문 추출(root)", body == "root")
check("종료코드 0 파싱", rc == 0)
body2, rc2 = strip_marker("bash: foo: command not found\n__M_127", "__M_")
check("실패 종료코드 127", rc2 == 127)
body3, rc3 = strip_marker("partial output no marker yet", "__M_")
check("마커 없으면 rc None", rc3 is None and "partial" in body3)
# ANSI 이스케이프 제거
b4, _ = strip_marker("\x1b[0;31mred\x1b[0m\n__M_0", "__M_")
check("ANSI 제거", b4 == "red")

print("\n=== ReverseShellSession (수신 transport 주입형) ===")
rs = ReverseShellSession("10.10.14.13", 4444)
check("transport 미주입 → LISTENING", rs.state == ShellState.LISTENING)
check("transport 미주입 → alive False", rs.alive is False)
check("리스너 명령 생성", rs.listener_command() == "nc -lvnp 4444")
check("페이로드 생성(revshell 재사용)", len(rs.payloads()) > 0)
check("페이로드에 LHOST/LPORT 반영", any("10.10.14.13" in p.payload and "4444" in p.payload
                                        for p in rs.payloads()))
try:
    rs.run("id"); check("미주입 run 거부", False)
except RuntimeError as e:
    check("미주입 run 거부(명확한 메시지)", "transport 미주입" in str(e))

# 가짜 transport 주입(테스트용) — 실제 소켓 대신 프레임을 받아 정형 출력 반환
def fake_transport(framed):
    # framed = "id; echo __MARKER_$?" → 마커를 그대로 echo 한 것처럼 흉내
    marker = framed.split("echo ", 1)[1]  # "__..._$?"
    tok = marker.replace("$?", "")
    return f"uid=0(root) gid=0(root)\n{tok}0\n"
rs.attach(fake_transport)
check("attach 후 CONNECTED", rs.state == ShellState.CONNECTED and rs.alive is True)
res = rs.run("id")
check("run 본문만 반환(마커 제거)", res == "uid=0(root) gid=0(root)")
check("종료코드 기록", rs.last_rc == 0)
rs.close()
check("close 후 CLOSED", rs.state == ShellState.CLOSED)

print("\n=== WebRceSession (웹 RCE 명령 채널, C) ===")
wr = WebRceSession("http://connected.htb/admin/config.php", "cmd", method="POST", inject="body")
check("http_fn 미주입 → INIT", wr.state == ShellState.INIT)
check("http_fn 미주입 → alive False", wr.alive is False)
spec = wr.build_request("id")
check("POST body 에 cmd 주입", spec["method"] == "POST" and spec["data"]["cmd"] == "id")
check("url 유지", spec["url"].endswith("/admin/config.php"))
try:
    wr.run("id"); check("미주입 run 거부", False)
except RuntimeError as e:
    check("미주입 run 거부(명확한 메시지)", "http_fn 미주입" in str(e))

# query 주입 + extra_params
wq = WebRceSession("http://t/x.php", "c", inject="query", extra_params={"auth": "1"})
sq = wq.build_request("whoami")
check("query 에 cmd 주입", sq["params"]["c"] == "whoami")
check("extra_params 병합", sq["params"]["auth"] == "1")

# header 주입
wh = WebRceSession("http://t/x", "X-Cmd", inject="header")
check("header 에 cmd 주입", wh.build_request("id")["headers"]["X-Cmd"] == "id")
check("잘못된 inject 거부", _raises(lambda: WebRceSession("u", "c", inject="bad")))

# 가짜 http_fn 주입 → 프레이밍/파싱 동작
def fake_http(spec):
    framed = spec["data"]["cmd"]                 # "id; echo __WEB_$?"
    tok = framed.split("echo ", 1)[1].replace("$?", "")
    return f"<pre>uid=33(www-data)\n{tok}0\n</pre>"
wr.attach(fake_http)
check("attach 후 CONNECTED", wr.state == ShellState.CONNECTED and wr.alive is True)
res = wr.run("id")
check("웹 RCE run 본문만(마커·HTML 잔재 처리)", "uid=33(www-data)" in res and "__HTBWEB" not in res)
check("종료코드 기록", wr.last_rc == 0)

print("\n=== 생성 전용 경계(불변) 자기점검 ===")
import htb_agent.shell_session as ss  # noqa: E402
for mod in ("socket", "subprocess", "requests", "pty", "os", "urllib", "http"):
    check(f"소켓/HTTP/실행 모듈 미임포트: {mod!r}", not hasattr(ss, mod))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
