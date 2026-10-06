# 실행: htb-agent 디렉토리에서  python3 tests/test_recommend.py
# 다음 선택지 제안(휴먼인더루프) — 근거 포함, 사람이 선택·승인. 자동 실행 아님.
import sys
sys.path.insert(0, "src")
from htb_agent import recommend as rc
from htb_agent import diagnostics as dx

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")


class R:  # 가짜 리포트(필요 필드만)
    def __init__(self):
        self.blockers = []
        self.enum_findings = []
        self.llm_findings = []
        self.phase_status = {}
        self.manual_suggestions = []


print("=== 대상 응답(진단) → 선택지 ===")
r = R()
r.blockers = [("curl -i http://t/admin", dx.FailureDiagnosis("http-403", "접근 금지(403)", True, "헤더 우회 각도 검토"))]
s = rc.propose(r)
check("403 → 대응 선택지 생성", any("403" in x.title or "접근 금지" in x.title for x in s.items))
check("근거(힌트) 포함", any("헤더 우회" in x.rationale for x in s.items))

print("\n=== 환경 문제 → '먼저 확인'(경로 실패 아님) ===")
r = R()
r.blockers = [("c", dx.FailureDiagnosis("conn-refused", "연결 거부", False, "포트 확인")),
              ("c2", dx.FailureDiagnosis("timeout", "타임아웃", False, "속도 확인"))]
s = rc.propose(r)
env = [x for x in s.items if x.source == "diagnosis" and "환경" in x.title]
check("환경 선택지 1개로 묶임", len(env) == 1)
check("경로 실패 아님 명시", any("경로 실패 아님" in x.title or "섣불리 버리지" in x.rationale for x in s.items))
check("환경 선택지 우선순위 높음(먼저)", s.items[0].source == "diagnosis")

print("\n=== 대기 단계 → 전제 확보 안내 ===")
r = R()
r.phase_status = {"privesc": "대기(전제 미충족: 자격 없음)", "enum": "진행"}
s = rc.propose(r)
check("대기 단계 선택지", any(x.source == "phase" and "전제" in x.title for x in s.items))
check("진행 단계는 선택지 아님", not any("열거" in x.title and x.source == "phase" for x in s.items))

print("\n=== KB 수동 제안 → 구체 후보 ===")
r = R()
r.manual_suggestions = ["hydra -L u.txt -P rockyou.txt ssh://t   # 브루트"]
s = rc.propose(r)
check("수동 제안이 선택지로", any(x.source == "kb" and "hydra" in x.ref for x in s.items))

print("\n=== 아무 막힘 없으면 선택지 없음 ===")
check("깨끗한 리포트 → has_items False", not rc.propose(R()).has_items)

print("\n=== 상한·우선순위 ===")
r = R()
r.blockers = [("c", dx.FailureDiagnosis("http-403", "403", True, "h")),
              ("c", dx.FailureDiagnosis("http-404", "404", True, "h2"))]
r.manual_suggestions = [f"cmd{i}" for i in range(10)]
s = rc.propose(r, max_items=5)
check("max_items 상한 준수", len(s.items) <= 5)
check("대상 응답이 KB 제안보다 먼저", s.items[0].source in ("diagnosis",))

print("\n=== 오케스트레이터 통합(리포트 NEXT OPTIONS) ===")
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.runner import FakeRunner, RunOutput
from htb_agent.tools.recon import auto_approve_in_scope
from htb_agent.knowledge import KnowledgeBase
from htb_agent.orchestrator import Orchestrator
XML = ('<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.129.1.5"/>'
       '<ports><port protocol="tcp" portid="80"><state state="open"/>'
       '<service name="http" product="Apache"/></port></ports></host></nmaprun>')
def guard():
    g = ScopeGuard.from_cidr_strings(); g.bind_target("10.129.1.5"); return g
def responder(c):
    if c.startswith("nmap"): return RunOutput(c, stdout=XML)
    if c.startswith("curl"): return RunOutput(c, stdout="HTTP/1.1 403 Forbidden\r\n\r\n")
    return RunOutput(c, stdout="ok")
rep = Orchestrator(guard(), FakeRunner(responder), KnowledgeBase.load(),
                   auto_approve_in_scope, is_tool_available=lambda b: True).run()
check("done 유지", rep.status == "done")
check("리포트에 NEXT OPTIONS 섹션", "NEXT OPTIONS" in rep.summary())
check("자동 실행 아님 명시", "자동 실행 아님" in rep.summary() and "승인" in rep.summary())

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
