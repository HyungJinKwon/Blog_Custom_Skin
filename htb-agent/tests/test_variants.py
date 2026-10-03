# 실행: htb-agent 디렉토리에서  python3 tests/test_variants.py
import sys
sys.path.insert(0, "src")
from htb_agent.variants import expand_variants
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.runner import FakeRunner, RunOutput
from htb_agent.tools.recon import auto_approve_in_scope
from htb_agent.knowledge import KnowledgeBase
from htb_agent.orchestrator import Orchestrator

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== expand_variants ===")
check("max_variants=1 → 기본만", expand_variants("nmap -sV 10.1.1.1", 1) == ["nmap -sV 10.1.1.1"])
v = expand_variants("nmap -sV 10.1.1.1", 3)
check("nmap 변형 3개", len(v) == 3 and v[0] == "nmap -sV 10.1.1.1")
check("nmap 변형에 옵션 추가", any("-T4" in c for c in v) and any("-sC" in c for c in v))
check("동일 타겟 유지", all("10.1.1.1" in c for c in v))
# 이미 있는 플래그는 중복 안 함
v2 = expand_variants("nmap -sV -T4 10.1.1.1", 4)
check("기존 -T4 중복 추가 안 함", sum(c.count("-T4") for c in v2) == len([c for c in v2 if "-T4" in c]) and
      all(c.count("-T4") <= 1 for c in v2))
# gobuster 확장자 변형
vg = expand_variants("gobuster dir -u http://10.1.1.1 -w w.txt", 2)
check("gobuster 확장자 변형", any("-x php,html,txt" in c for c in vg))
# 미등록 도구 → 기본만
check("미등록 도구 기본만", expand_variants("weirdtool 10.1.1.1", 5) == ["weirdtool 10.1.1.1"])

print("\n=== 오케스트레이터 변형 적용 ===")
XML = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.129.1.5"/><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache"/></port>
</ports></host></nmaprun>"""
def guard():
    g = ScopeGuard.from_cidr_strings(); g.bind_target("10.129.1.5"); return g
def runner():
    return FakeRunner(lambda c: RunOutput(c, stdout=XML) if c.startswith("nmap") else RunOutput(c, stdout="ok"))
ALL = lambda b: True

# 변형 1(기본): 각 베이스 명령 1회
rep1 = Orchestrator(guard(), runner(), KnowledgeBase.load(), auto_approve_in_scope,
                    max_variants=1, max_enum=20, is_tool_available=ALL).run()
base_cmds = {f.command for f in rep1.enum_findings}
# 변형 3: 더 많은 명령(옵션 조합) 시도
rep3 = Orchestrator(guard(), runner(), KnowledgeBase.load(), auto_approve_in_scope,
                    max_variants=3, max_enum=20, is_tool_available=ALL).run()
var_cmds = {f.command for f in rep3.enum_findings}
check("변형3 이 변형1 보다 많은 명령", len(var_cmds) > len(base_cmds))
check("변형에 옵션 조합 포함", any(("-x php" in c or "-mc all" in c or "-L" in c or "-a 3" in c) for c in var_cmds))
check("기본 명령도 그대로 포함", base_cmds <= var_cmds)
# 상한 존중(무한 아님)
check("max_enum 상한 준수", len([f for f in rep3.enum_findings]) <= 20)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
