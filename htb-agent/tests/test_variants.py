# 실행: htb-agent 디렉토리에서  python3 tests/test_variants.py
import sys
sys.path.insert(0, "src")
from htb_agent.variants import expand_variants, fragment_of
from htb_agent.variant_stats import VariantStats
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

print("\n=== 실행 중 변형 결과가 학습 통계에 기록 ===")
vstats = VariantStats()
Orchestrator(guard(), runner(), KnowledgeBase.load(), auto_approve_in_scope,
             max_variants=3, max_enum=20, variant_stats=vstats, is_tool_available=ALL).run()
check("변형 실행 결과가 기록됨", len(vstats.stats) >= 1)
check("기록 키에 fragment 포함", all("\x1f" in k for k in vstats.stats))

print("\n=== fragment_of ===")
check("추가 fragment 추출", fragment_of("gobuster dir -u x", "gobuster dir -u x -t 50") == "-t 50")
check("기본 명령이면 빈 문자열", fragment_of("gobuster dir -u x", "gobuster dir -u x") == "")

print("\n=== VariantStats 학습·랭킹 ===")
vs = VariantStats()
# gobuster 변형 중 '-t 50' 을 성공, '-x php,html,txt' 를 실패로 여러번 기록
for _ in range(5):
    vs.record("gobuster", "-t 50", True)
    vs.record("gobuster", "-x php,html,txt", False)
frags = ["-x php,html,txt", "-t 50", "-s 200,204,301,302,307,401,403"]
ranked = vs.rank("gobuster", frags)
check("성공 변형이 실패 변형보다 앞", ranked.index("-t 50") < ranked.index("-x php,html,txt"))
check("미관측 변형은 중립(0.5) 근처", 0.4 < vs.score("gobuster", "-s 200,204,301,302,307,401,403") < 0.6)
check("성공 변형 점수 높음", vs.score("gobuster", "-t 50") > 0.7)
check("실패 변형 점수 낮음", vs.score("gobuster", "-x php,html,txt") < 0.3)

print("\n=== 학습이 expand_variants 순서에 반영 ===")
# 통계가 있으면 -t 50 변형이 먼저 나와야(기본은 항상 첫째)
ev = expand_variants("gobuster dir -u http://t/", 3, vs)
check("기본은 여전히 첫째", ev[0] == "gobuster dir -u http://t/")
check("학습된 -t 50 변형이 2번째", ev[1].endswith("-t 50"))

print("\n=== 직렬화 라운드트립 ===")
import json as _json
d = vs.to_dict(); vs2 = VariantStats.from_dict(_json.loads(_json.dumps(d)))
check("to_dict/from_dict 보존", vs2.score("gobuster", "-t 50") == vs.score("gobuster", "-t 50"))
check("빈 binary/fragment 무시", (VariantStats().record("", "x", True) or True) and len(VariantStats().stats) == 0)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
