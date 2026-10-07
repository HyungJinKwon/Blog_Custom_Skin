# 실행: htb-agent 디렉토리에서  python3 tests/test_optimize.py
# 최적화 회귀 — 캐시가 '정확성'을 해치지 않는지(무효화·결과 동일) + export 누락 보완.
import json
import sys
sys.path.insert(0, "src")
from htb_agent.knowledge import KnowledgeBase
from htb_agent.command_validator import validate, _check_shell_syntax

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")


print("=== RAG 소문자 캐시: 결과 동일 + 노트 추가 시 무효화 ===")
kb = KnowledgeBase(notes=["Alpha SMB note", "Beta HTTP note"])
check("초기 검색", kb.relevant_notes(["smb"], 1) == ["Alpha SMB note"])
kb.notes.append("Gamma KERBEROAST note")           # 런타임 주입(자율학습 경로와 동일)
check("추가된 노트가 즉시 검색됨(캐시 무효화)",
      kb.relevant_notes(["kerberoast"], 1) == ["Gamma KERBEROAST note"])
kb.notes[-1] = "Delta LDAP note"                    # 마지막 원소 교체
check("교체된 노트 반영", kb.relevant_notes(["ldap"], 1) == ["Delta LDAP note"])
kb2 = KnowledgeBase(notes=[])
check("빈 KB 안전", kb2.relevant_notes(["x"], 3) == [])

print("\n=== 구문검사 메모이즈: 결과 동일 ===")
_check_shell_syntax.cache_clear()
ok1 = validate("nmap -sV 10.129.1.5").ok
ok2 = validate("nmap -sV 10.129.1.5").ok
check("같은 명령 재검증 결과 동일", ok1 == ok2 is True)
bad1 = validate('echo "unterminated').ok
bad2 = validate('echo "unterminated').ok
check("구문 오류도 캐시 후 동일하게 거부", bad1 is False and bad2 is False)
check("캐시 적중 발생", _check_shell_syntax.cache_info().hits >= 1)

print("\n=== recommend: 미리 계산한 반복 분석 재사용 ===")
from htb_agent import recommend, repetition
class R:
    blockers = []; enum_findings = []; llm_findings = []
    phase_status = {}; manual_suggestions = []
rr = repetition.RepetitionReport(stalled=True)
s = recommend.propose(R(), repetition=rr)
check("전달된 분석 결과 사용(정체 → 각도 전환 선택지)",
      any(x.source == "repetition" for x in s.items))

print("\n=== JSON export 누락 보완 ===")
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.runner import FakeRunner, RunOutput
from htb_agent.tools.recon import auto_approve_in_scope
from htb_agent.orchestrator import Orchestrator
from htb_agent.report_export import to_json
XML = ('<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.129.1.5"/>'
       '<ports><port protocol="tcp" portid="80"><state state="open"/>'
       '<service name="http" product="Apache"/></port></ports></host></nmaprun>')
def guard():
    g = ScopeGuard.from_cidr_strings(); g.bind_target("10.129.1.5"); return g
def responder(c):
    if c.startswith("nmap"): return RunOutput(c, stdout=XML)
    if c.startswith("curl"):
        return RunOutput(c, stdout="HTTP/1.1 403 Forbidden\r\n\r\nHTB{export_flag}")
    return RunOutput(c, stdout="ok")
rep = Orchestrator(guard(), FakeRunner(responder), KnowledgeBase.load(), auto_approve_in_scope,
                   flag_kind="single", flag_prefixes=("HTB",),
                   is_tool_available=lambda b: True).run()
d = json.loads(to_json(rep))
for key in ("blockers", "flag_provenance", "learn", "next_options"):
    check(f"export 에 '{key}' 포함", key in d)
check("blockers 구조화(카테고리·대상여부)",
      any(b["category"] == "http-403" and b["is_target"] for b in d["blockers"]))
check("flag_provenance 구조화(verdict)",
      any(p["verdict"] == "exploit-derived" for p in d["flag_provenance"]))
check("next_options 가 JSON 직렬화됨", isinstance(d["next_options"], list))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
