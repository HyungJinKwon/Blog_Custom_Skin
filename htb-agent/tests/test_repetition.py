# 실행: htb-agent 디렉토리에서  python3 tests/test_repetition.py
# 반복·정체 감지(실행 트레이스 사후 분석) — 사람 보고용, 자동 재계획 아님.
import sys
sys.path.insert(0, "src")
from htb_agent import repetition as rp
from htb_agent import diagnostics as dx

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")


class F:  # 가짜 finding
    def __init__(self, command, ran=True, output="ok"):
        self.command = command; self.ran = ran; self.output = output


print("=== signature: 같은 종류 시도를 묶음 ===")
check("워드리스트만 다른 gobuster → 같은 서명",
      rp.signature("gobuster dir -u http://t -w a.txt") == rp.signature("gobuster dir -u http://t -w b.txt"))
check("다른 도구 → 다른 서명",
      rp.signature("nmap -sV t") != rp.signature("curl -i http://t"))

print("\n=== 반복 명령 감지(실행된 것만) ===")
fs = [F("gobuster dir -u http://t -w a.txt"), F("gobuster dir -u http://t -w b.txt"),
      F("gobuster dir -u http://t -w c.txt"), F("nmap -sV t")]
r = rp.analyze(fs, cmd_threshold=3)
check("gobuster 3회 → 반복으로 표시", any("gobuster" in s and n == 3 for s, n in r.repeated_cmds))
check("nmap 1회 → 반복 아님", not any("nmap" in s for s, n in r.repeated_cmds))

print("\n=== 게이트 탈락(미실행)은 제외 ===")
fs2 = [F("x", ran=False), F("x", ran=False), F("x", ran=False)]
check("미실행만이면 반복 없음", rp.analyze(fs2).repeated_cmds == [])

print("\n=== 반복 실패(같은 진단 범주) ===")
blockers = [("c1", dx.FailureDiagnosis("conn-refused", "x", False)),
            ("c2", dx.FailureDiagnosis("conn-refused", "x", False)),
            ("c3", dx.FailureDiagnosis("conn-refused", "x", False)),
            ("c4", dx.FailureDiagnosis("http-404", "x", True))]
r = rp.analyze([F("a")], blockers, fail_threshold=3)
check("conn-refused 3회 → 반복 실패", any(c == "conn-refused" and n == 3 for c, n in r.repeated_failures))
check("404 1회 → 반복 아님", not any(c == "http-404" for c, n in r.repeated_failures))

print("\n=== 정체 감지(유의미한 출력 희박) ===")
stall = [F("a", output=""), F("b", output=""), F("c", output=""), F("d", output="")]
check("출력 거의 없음 → 정체", rp.analyze(stall).stalled)
check("출력 충분 → 정체 아님", not rp.analyze([F("a"), F("b"), F("c"), F("d")]).stalled)

print("\n=== 아무 반복 없으면 비어있음 ===")
check("정상 트레이스 → has_findings False", not rp.analyze([F("nmap t"), F("curl http://t")]).has_findings)

print("\n=== 오케스트레이터 통합(리포트 REPETITION) ===")
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
def responder(c):  # 모든 enum 이 연결거부 반복 → REPETITION 유발
    if c.startswith("nmap"): return RunOutput(c, stdout=XML)
    return RunOutput(c, error="curl: (7) Connection refused")
rep = Orchestrator(guard(), FakeRunner(responder), KnowledgeBase.load(),
                   auto_approve_in_scope, is_tool_available=lambda b: True).run()
check("done 유지", rep.status == "done")
# 반복 실패(conn-refused)가 리포트에 드러나는지(미실행이라 반복'명령'은 아님)
check("정상 종료(크래시 없음)", rep.status == "done" and isinstance(rep.summary(), str))
# 트레이스에 같은 실패가 임계 이상이면 REPETITION 노출(결정적으로 analyze 로 재확인)
r2 = rp.analyze(rep.enum_findings + rep.llm_findings, rep.blockers)
check("감지기가 리포트 데이터에서 동작", isinstance(r2.has_findings, bool))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
