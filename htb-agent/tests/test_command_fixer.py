# 실행: htb-agent 디렉토리에서  python3 tests/test_command_fixer.py
# Results Verifier(AutoPentester): 범위 밖 명령의 타겟 자동 교정(복구만, 안전 경계).
import sys
sys.path.insert(0, "src")
from htb_agent.command_fixer import correct_target
from htb_agent.scope_guard import ScopeGuard

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

def g(ip="10.129.1.5", att="10.10.14.9"):
    gg = ScopeGuard.from_cidr_strings(["10.129.0.0/16"])
    gg.bind_target(ip)
    if att:
        gg.add_attacker_ip(att)
    return gg

print("=== 자리표시자 → 타겟 ===")
for ph in ["<target>", "<IP>", "<rhost>", "TARGET_IP", "<victim>"]:
    cmd, why = correct_target(f"curl http://{ph}/x", g())
    check(f"{ph} 치환", cmd == "curl http://10.129.1.5/x" and "자리표시자" in why)

print("\n=== 잘못된 타겟 IP → 교정(하나뿐일 때만) ===")
cmd, why = correct_target('msfconsole -x "set RHOST 192.168.1.10; run"', g())
check("사설 IP 교정", "10.129.1.5" in cmd and "192.168.1.10" not in cmd and "IP" in why)
cmd, why = correct_target("nmap 10.129.9.9", g())
check("타겟대역 다른 IP 교정", cmd == "nmap 10.129.1.5")

print("\n=== 손대면 안 되는 경우 ===")
check("공격자 IP(LHOST) 보존", correct_target("msfvenom LHOST=10.10.14.9 LPORT=4444", g()) == (
    "msfvenom LHOST=10.10.14.9 LPORT=4444", ""))
check("이미 타겟이면 그대로", correct_target("curl http://10.129.1.5/", g()) == (
    "curl http://10.129.1.5/", ""))
check("IP 두 개 이상이면 모호 → 안 바꿈", correct_target("nmap 10.129.9.9 10.129.8.8", g())[0]
      == "nmap 10.129.9.9 10.129.8.8")
check("공인 IP 는 안 바꿈(오작동 방지)", correct_target("curl http://8.8.8.8/", g())[0]
      == "curl http://8.8.8.8/")
check("루프백 보존", correct_target("curl http://127.0.0.1/", g())[0] == "curl http://127.0.0.1/")
check("타겟 미바인딩이면 무변경", correct_target("curl http://<target>/",
      ScopeGuard.from_cidr_strings()) == ("curl http://<target>/", ""))

print("\n=== 오케스트레이터 복구(범위 밖만 교정) ===")
from htb_agent.knowledge import KnowledgeBase
from htb_agent.llm.fake_provider import FakeProvider
from htb_agent.llm.base import LLMResponse
from htb_agent.llm.router import LLMRouter
from htb_agent.orchestrator import Orchestrator
from htb_agent.tools.recon import auto_approve_in_scope
from htb_agent.tools.runner import FakeRunner, RunOutput

WEB = ('<?xml version="1.0"?><nmaprun><host><status state="up"/>'
       '<address addr="10.129.1.5"/><ports><port protocol="tcp" portid="80">'
       '<state state="open"/><service name="http"/></port></ports></host></nmaprun>')
calls = []
def resp(cmd):
    calls.append(cmd)
    if cmd.startswith("nmap") and "-oX" in cmd:
        return RunOutput(cmd, stdout=WEB)
    return RunOutput(cmd, stdout="ok")
kb = KnowledgeBase.load()
# LLM 이 '범위 밖' 타겟을 제안 → 교정되어 실행되는지(=실제 실행 명령에 바인딩 타겟이 들어감)
tc = [{"name": "propose_commands", "input": {"commands": [
    {"command": "curl -s http://192.168.50.50/admin"}]}}]
prov = FakeProvider(lambda s, u, t: LLMResponse(text="", model="f", tool_calls=tc))

def guard():
    from htb_agent.scope_guard import ScopeGuard as SG
    gg = SG.from_cidr_strings(); gg.bind_target("10.129.1.5"); return gg

orc = Orchestrator(guard(), FakeRunner(resp), kb, auto_approve_in_scope,
                   llm_router=LLMRouter(prov), is_tool_available=lambda b: True,
                   max_sweeps=1, max_rounds=1)
orc.run()
fixed_ran = any("curl -s http://10.129.1.5/admin" == c for c in calls)
orig_ran = any("192.168.50.50" in c for c in calls)
check("범위 밖 제안이 타겟으로 교정되어 실행", fixed_ran and not orig_ran)

# fix_commands=False 면 교정 안 하고 거부(실행 안 됨)
calls.clear()
orc2 = Orchestrator(guard(), FakeRunner(resp), kb, auto_approve_in_scope,
                    llm_router=LLMRouter(FakeProvider(
                        lambda s, u, t: LLMResponse(text="", model="f", tool_calls=tc))),
                    is_tool_available=lambda b: True, fix_commands=False,
                    max_sweeps=1, max_rounds=1)
orc2.run()
check("fix_commands=False 면 교정 안 함(범위 밖 미실행)",
      not any("10.129.1.5/admin" in c for c in calls))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
