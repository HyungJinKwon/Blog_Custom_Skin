# 실행: htb-agent 디렉토리에서  python3 tests/test_vhost_autoreg.py
# vhost 자동 등록(리다이렉트 발견 → 스코프 in-scope) + VM 기본환경 설정 회귀 테스트.
import os
import sys
import tempfile
sys.path.insert(0, "src")
from htb_agent.config import Config, ConfigError, load_config  # noqa: E402
from htb_agent.knowledge import KnowledgeBase  # noqa: E402
from htb_agent.orchestrator import Orchestrator, OrchestrationReport  # noqa: E402
from htb_agent.scope_guard import ScopeGuard  # noqa: E402
from htb_agent.tools.recon import auto_approve_in_scope  # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

def orc(tmp_hosts):
    g = ScopeGuard.from_cidr_strings(); g.bind_target("10.129.245.100")
    o = Orchestrator(g, FakeRunner(lambda c: RunOutput(c, stdout="x")), KnowledgeBase.load(),
                     auto_approve_in_scope, is_tool_available=lambda b: True)
    o._vhost_seen = set(); o.hosts_map = None; o._hosts_path = tmp_hosts
    return o, g

print("=== vhost 자동 등록: 리다이렉트 → 스코프 in-scope ===")
with tempfile.TemporaryDirectory() as d:
    hosts = os.path.join(d, "hosts")   # 실제 /etc/hosts 안 건드림
    open(hosts, "w").close()           # 존재+쓰기 가능(=권한 있는 상황 모사)
    o, g = orc(hosts)
    rep = OrchestrationReport(target="10.129.245.100")
    out = "HTTP 301 Moved Permanently | Server=Apache | → http://connected.htb/ | 보안헤더 누락=CSP"
    o._maybe_register_vhost(rep, out)
    check("connected.htb 를 타겟 IP 로 hosts_map 등록",
          (o.hosts_map or {}).get("connected.htb") == "10.129.245.100")
    # 스코프 가드가 connected.htb 를 in-scope(TARGET)로 인식하는지
    sres = g.inspect_command("curl http://connected.htb/", hosts_map=o.hosts_map)
    check("등록 후 connected.htb 명령이 범위 안(auto_allowed)", sres.auto_allowed)
    check("권한 있으면 hosts 에 자동 기록", "connected.htb" in open(hosts).read())
    # 같은 vhost 재등장 시 중복 처리 안 함
    o._maybe_register_vhost(rep, out)
    check("중복 vhost 재등록 안 함", len(o.hosts_map) == 1)

print("\n=== 권한 없음(쓰기 불가) → 1회 안내만 ===")
with tempfile.TemporaryDirectory() as d:
    # 존재하지 않는 디렉터리의 경로 → open/access 모두 실패(root 여도) → 안내 경로
    hosts = os.path.join(d, "nope", "hosts")
    o, g = orc(hosts)
    rep = OrchestrationReport(target="10.129.245.100")
    o._maybe_register_vhost(rep, "→ https://dev.connected.htb/ foo")
    hinted = [m for m in rep.manual_suggestions if "sudo tee -a /etc/hosts" in m]
    check("쓰기 불가 → sudo tee 안내 1회", len(hinted) == 1)
    check("안내해도 스코프 등록은 됨", (o.hosts_map or {}).get("dev.connected.htb") == "10.129.245.100")

print("\n=== VM 기본환경: config 로 sandbox/vm_ssh 지정 ===")
with tempfile.TemporaryDirectory() as d:
    cfgp = os.path.join(d, "config.json")
    with open(cfgp, "w") as f:
        f.write('{"sandbox":"vm","vm_ssh":"kali@192.168.56.10","vm_ssh_port":2222,'
                '"vm_sudo":true,"vm_confine":true}')
    c = load_config(cfgp)
    check("sandbox=vm 파싱", c.sandbox == "vm")
    check("vm_ssh 파싱", c.vm_ssh == "kali@192.168.56.10")
    check("vm_ssh_port 파싱", c.vm_ssh_port == 2222)
    check("vm_sudo/confine 파싱", c.vm_sudo is True and c.vm_confine is True)

def raises(fn):
    try: fn(); return False
    except ConfigError: return True
check("vm_sudo 비불리언 → ConfigError", raises(lambda: Config.from_dict({"vm_sudo": "yes"})))
check("sandbox=vm 는 허용값", not raises(lambda: Config.from_dict({"sandbox": "vm"})))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
