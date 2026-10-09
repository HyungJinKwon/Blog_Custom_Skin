# 실행: htb-agent 디렉토리에서  python3 tests/test_sandbox.py
# 실제 docker 없이 exec_fn 을 주입해 샌드박스 로직(정책 생성·검증·egress 허용) 검증.
import sys
import tempfile

sys.path.insert(0, "src")
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.sandbox import (
    DockerSandbox, SandboxError, ShellRunner, allowlist_for, egress_rules,
)

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")


class FakeProc:
    def __init__(self, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


print("=== egress 규칙 생성 ===")
rules = egress_rules(["10.129.1.5/32"], lports=[4444])
check("기본 OUTPUT DROP", ":OUTPUT DROP [0:0]" in rules)
check("타겟만 ACCEPT", "-A OUTPUT -d 10.129.1.5/32 -j ACCEPT" in rules)
check("리스너 포트 수신 허용", "--dport 4444 -j ACCEPT" in rules)
check("타겟 외 대역 미허용", "0.0.0.0" not in rules)
for bad in [[], ["0.0.0.0/0"], ["not-an-ip"]]:
    try:
        egress_rules(bad); check(f"거부: {bad}", False)
    except (SandboxError, ValueError):
        check(f"거부: {bad}", True)

print("\n=== allowlist_for(바인딩된 타겟만) ===")
g = ScopeGuard.from_cidr_strings()
g.bind_target("10.129.1.5")
cidrs, hosts = allowlist_for(g)
check("타겟 /32 만 허용", cidrs == ["10.129.1.5/32"])

g2 = ScopeGuard.from_cidr_strings(["10.129.0.0/16"], enforce_ranges=False,
                                  allow_hostname_target=True)
g2.bind_target("chall.example.com")
cidrs2, hosts2 = allowlist_for(g2, resolver=lambda h: ["10.129.9.9"])
check("호스트명 해석 IP 허용", "10.129.9.9/32" in cidrs2)
check("컨테이너 hosts 고정", hosts2.get("chall.example.com") == "10.129.9.9")
try:
    allowlist_for(g2, resolver=lambda h: [])   # 해석 실패
    check("해석 실패 시 거부", False)
except SandboxError:
    check("해석 실패 시 거부", True)

print("\n=== DockerSandbox 수명주기(주입 exec) ===")
calls = []
def fake_exec(args, **kw):
    calls.append(args)
    joined = " ".join(args)
    if "iptables-restore" in joined or "ip6tables-restore" in joined:
        return FakeProc(0)
    if "ip6tables -S OUTPUT" in joined:       # v6 차단 적용 후 상태(기본 DROP)
        return FakeProc(0, out="-P OUTPUT DROP\n")
    if "iptables -S OUTPUT" in joined:
        return FakeProc(0, out="-P OUTPUT DROP\n-A OUTPUT -d 10.129.1.5/32 -j ACCEPT\n")
    if "-P OUTPUT ACCEPT" in joined:          # agent 사용자 변조 시도 → 거부(권한 없음)
        return FakeProc(1, err="Permission denied")
    if args[:2] == ["docker", "run"]:
        return FakeProc(0, out="containerid\n")
    if "command -v" in joined:
        return FakeProc(0 if "nmap" in joined else 1)
    return FakeProc(0, out="ok")

tmp = tempfile.mkdtemp(prefix="sbx-")
sb = DockerSandbox(tmp, ["10.129.1.5/32"], lports=[4444], exec_fn=fake_exec)
run_args = sb.run_args()
check("no-new-privileges", "no-new-privileges" in " ".join(run_args))
check("워크스페이스 마운트", any(tmp in a for a in run_args))
sb.start()
check("시작 성공(정책 적용·검증)", sb.started)
check("비root 변조 시도 검증 수행", any("-P OUTPUT ACCEPT" in " ".join(c) for c in calls))
check("IPv6 egress 차단 검증 수행", any("ip6tables -S OUTPUT" in " ".join(c) for c in calls))
check("has_tool: 설치된 도구", sb.has_tool("nmap"))
check("has_tool: 미설치 도구", not sb.has_tool("doesnotexist"))
out = sb.run("echo hi | grep hi", timeout=10)
check("run: bash -c 로 셸 문법 전달", out.launched)
check("실행 인자에 timeout+bash -c", any(
    "timeout" in c and "bash" in c for c in [" ".join(x) for x in calls]))
check("shell=True 플래그", sb.shell is True)
check("contained=True 플래그", sb.contained is True)

print("\n=== 변조 가능 시 start 거부(fail-closed) ===")
def tamper_exec(args, **kw):
    joined = " ".join(args)
    if args[:2] == ["docker", "run"]:
        return FakeProc(0, out="cid\n")
    if "iptables-restore" in joined or "ip6tables-restore" in joined:
        return FakeProc(0)
    if "iptables -S OUTPUT" in joined:
        return FakeProc(0, out="-P OUTPUT DROP\n")
    if "-P OUTPUT ACCEPT" in joined:
        return FakeProc(0)        # 변조 성공(=위험) → start 가 거부해야 함
    return FakeProc(0)
sb2 = DockerSandbox(tmp, ["10.129.1.5/32"], exec_fn=tamper_exec)
try:
    sb2.start(); check("변조 가능 → SandboxError", False)
except SandboxError:
    check("변조 가능 → SandboxError", True)

print("\n=== 정책 적용 실패 시 거부 ===")
def badpolicy_exec(args, **kw):
    joined = " ".join(args)
    if args[:2] == ["docker", "run"]:
        return FakeProc(0, out="cid\n")
    if "iptables-restore" in joined:
        return FakeProc(1, err="iptables 적용 실패")
    return FakeProc(0)
try:
    DockerSandbox(tmp, ["10.129.1.5/32"], exec_fn=badpolicy_exec).start()
    check("정책 실패 → SandboxError", False)
except SandboxError:
    check("정책 실패 → SandboxError", True)

print("\n=== ShellRunner(네트워크 강제 없음) ===")
sr = ShellRunner()
check("contained=False", sr.contained is False)
check("shell=True", sr.shell is True)
out = sr.run("echo hi | tr a-z A-Z", timeout=10)
check("로컬 셸 파이프 동작", out.launched and "HI" in out.stdout)
check("stdin 닫힘(블록 안 함)", sr.run("cat", timeout=5).launched)

print("\n=== VMSandbox(SSH 실행, 주입 exec) ===")
from htb_agent.tools.sandbox import VMSandbox
import base64 as _b64

vm_calls = []
def vm_exec(args, **kw):
    vm_calls.append(args)
    j = " ".join(args)
    # ssh true (접속 확인)
    if j.endswith(" true"):
        return FakeProc(0)
    if "iptables -S OUTPUT" in j:
        return FakeProc(0, out="-P OUTPUT DROP\n-A OUTPUT -d 10.129.1.5/32 -j ACCEPT\n")
    if "iptables-restore" in j:
        return FakeProc(0)
    if "command -v nmap" in j:
        return FakeProc(0)
    if "command -v" in j:
        return FakeProc(1)
    if "base64 -d" in j:                 # run() 의 원격 명령
        return FakeProc(0, out="remote-output")
    return FakeProc(0, out="")

# user@host 형식 강제
try:
    VMSandbox("nohost", "/tmp/ws", ["10.129.1.5/32"]); check("user@host 아니면 거부", False)
except SandboxError:
    check("user@host 아니면 거부", True)

vm = VMSandbox("kali@10.0.0.9", "/tmp/ws", ["10.129.1.5/32"], lports=[4444],
               sudo=True, confine=True, exec_fn=vm_exec)
check("시작 전 contained=False", vm.contained is False)
vm.start()
check("접속 확인(ssh true) 호출", any(" ".join(a).endswith(" true") for a in vm_calls))
check("confine → contained=True", vm.contained is True)
check("egress 정책 검증 수행", any("iptables -S OUTPUT" in " ".join(a) for a in vm_calls))
check("has_tool 설치/미설치", vm.has_tool("nmap") and not vm.has_tool("doesnotexist"))

# run(): base64 로 명령 전달(따옴표 안전), ssh 로 원격 실행
out = vm.run("echo hi | grep hi", timeout=10)
runcall = next(a for a in vm_calls if "base64 -d" in " ".join(a))
remote = runcall[-1]
# 원격 문자열에서 b64 추출해 복원하면 원래 명령이어야
import re as _re
m = _re.search(r"echo ([A-Za-z0-9+/=]+) \| base64 -d", remote)
check("명령을 base64 로 전달", m is not None and
      _b64.b64decode(m.group(1)).decode() == "echo hi | grep hi")
check("원격에 timeout+bash", "timeout -k 5 10 bash" in remote and "cd /tmp/assassin-work" in remote)
check("run 결과 반환", out.launched and "remote-output" in out.stdout)
check("shell/real_exec 플래그", vm.shell is True and vm.real_exec is True)

# sync_file: scp 로 업로드(성공)
scp_calls = []
def vm_exec2(args, **kw):
    scp_calls.append(args)
    return FakeProc(0, out="")
vm2 = VMSandbox("kali@10.0.0.9", "/tmp/ws", ["10.129.1.5/32"], exec_fn=vm_exec2)
vm2.started = True
vm2.sync_file("/tmp/ws/exploit.py", "exploit.py")
check("sync_file 가 scp 호출", any(a and a[0] == "scp" for a in scp_calls))

# confine 실패(정책 검증 실패) → start 거부
def vm_exec_bad(args, **kw):
    j = " ".join(args)
    if j.endswith(" true"):
        return FakeProc(0)
    if "iptables -S OUTPUT" in j:
        return FakeProc(0, out="-P OUTPUT ACCEPT\n")   # DROP 아님 → 검증 실패
    return FakeProc(0)
vmb = VMSandbox("kali@10.0.0.9", "/tmp/ws", ["10.129.1.5/32"], confine=True, exec_fn=vm_exec_bad)
try:
    vmb.start(); check("egress 검증 실패 → SandboxError", False)
except SandboxError:
    check("egress 검증 실패 → SandboxError", True)

# confine 없이 → contained False(동적 실행 수동), 그래도 실행은 됨
vm3 = VMSandbox("kali@10.0.0.9", "/tmp/ws", ["10.129.1.5/32"], exec_fn=vm_exec)
vm3.start()
check("confine 없으면 contained=False", vm3.contained is False)


print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
