# 실행: htb-agent 디렉토리에서  python3 tests/test_paper_ideas.py
# 논문 아이디어(안전 재구현): 사실 출처 표시 · 승인 전 반복 경고 · 벤치 검증 풀이율/승인 부담.
import contextlib
import io
import sys
sys.path.insert(0, "src")
from htb_agent import bench as B
from htb_agent import main as M
from htb_agent.knowledge import KnowledgeBase, Rule
from htb_agent.llm.fake_provider import FakeProvider
from htb_agent.llm.router import LLMRouter
from htb_agent.orchestrator import Orchestrator
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.recon import auto_approve_in_scope
from htb_agent.tools.runner import FakeRunner, RunOutput
from htb_agent.world import WorldModel

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

T = "10.129.1.5"

print("=== 사실 출처 표시(왜 아는가) — world ===")
w = WorldModel(target=T)
w.add_cred("admin:pw", source="smbclient")
w.add_loot("해시: abc", source="dump")
w.add_vuln("CVE-2021-1", source="버전 매칭(VulnKB)")
w.add_cred("noorigin")   # 출처 없이
check("출처 저장", w.evidence.get("admin:pw") == "smbclient" and w.evidence.get("CVE-2021-1"))
check("context_lines 에 '(출처: ...)'", any("admin:pw (출처: smbclient)" in ln for ln in w.context_lines()))
check("출처 없으면 그대로", any("noorigin" in ln and "noorigin (출처" not in ln for ln in w.context_lines()))
check("to_dict 에 evidence 포함", "evidence" in w.to_dict() and w.to_dict()["evidence"]["admin:pw"] == "smbclient")

print("\n=== 수확된 크리덴셜/취약점에 출처가 붙음(오케스트레이터) ===")
XMLc = (f'<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="{T}"/>'
        '<ports><port protocol="tcp" portid="445"><state state="open"/>'
        '<service name="microsoft-ds"/></port></ports></host></nmaprun>')
def run_creds(c):
    if c.startswith("nmap"):
        return RunOutput(c, stdout=XMLc)
    return RunOutput(c, stdout="login username=operator password=Spring2024")
g = ScopeGuard.from_cidr_strings(); g.bind_target(T)
kb = KnowledgeBase(rules=[Rule(name="smb", phase="enum", ports=[445],
                               suggest=["smbclient -L //{t}/ -N"])], notes=[])
rep = Orchestrator(g, FakeRunner(run_creds), kb, auto_approve_in_scope,
                   is_tool_available=lambda b: True, max_sweeps=1).run()
src_lines = [ln for ln in rep.world.context_lines() if "출처:" in ln]
check("수확 크리덴셜에 도구 출처 표시", any("출처: smbclient" in ln for ln in src_lines))

print("\n=== 승인 전 반복 경고 — 같은 종류 실패의 재시도 ===")
XMLw = (f'<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="{T}"/>'
        '<ports><port protocol="tcp" portid="80"><state state="open"/>'
        '<service name="http"/></port></ports></host></nmaprun>')
def run404(c):
    if c.startswith("nmap"):
        return RunOutput(c, stdout=XMLw)
    return RunOutput(c, stdout="HTTP/1.1 404 Not Found\n\nnope")
seen_ctx = []
def llm(system, user, tier):
    if "분석가" in system:
        return "가설: x\n확신도: 중"
    # 매 라운드 같은 종류(gobuster)·다른 워드리스트 → 반복 경고 유발
    seen_ctx.append(user)
    return "gobuster dir -u http://{t}/ -w /usr/share/seclists/common.txt"
g2 = ScopeGuard.from_cidr_strings(); g2.bind_target(T)
kb2 = KnowledgeBase(rules=[Rule(name="w", phase="enum", ports=[80],
                                suggest=["gobuster dir -u http://{t}/ -w /usr/share/wordlists/a.txt"])], notes=[])
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    rep2 = Orchestrator(g2, FakeRunner(run404), kb2, auto_approve_in_scope,
                        llm_router=LLMRouter(FakeProvider(llm)),
                        is_tool_available=lambda b: True, max_sweeps=2, max_rounds=2).run()
out = buf.getvalue()
warned = [f for f in rep2.enum_findings + rep2.llm_findings if "앞서 실패한 같은 종류" in (f.note or "")]
check("반복 경고가 비고에 남음", len(warned) >= 1)
check("승인 전 경고가 화면에도 출력", "앞서 실패한 같은 종류" in out)
check("경고는 실행을 막지 않음(여전히 시도됨)", any(f.ran for f in rep2.enum_findings + rep2.llm_findings))
# 서로 다른 종류면 경고 없음
w3 = WorldModel(target=T)
o3 = Orchestrator(g2, FakeRunner(run404), kb2, auto_approve_in_scope, is_tool_available=lambda b: True)
from htb_agent.orchestrator import OrchestrationReport
r3 = OrchestrationReport(target=T)
check("실패 이력 없으면 경고 없음", o3._repetition_warning(r3, "curl -i http://x/") == "")

print("\n=== 벤치: 검증된 풀이율 + 승인 부담 ===")
KB = KnowledgeBase.load("knowledge")
SUITE = B.load_suite(B.default_suite_dir())
res = B.run_bench(SUITE, attempts=1, kb=KB)
st = B.summarize(SUITE, res)
t = B.totals(st)
check("성공 플래그는 모두 대상 상호작용 유래(검증됨)",
      all(r.verified for r in res if r.solved))
check("검증된 풀이율 100%(규칙 기준선)", t["verified_solve_rate"] == 1.0)
check("ChallengeStats.verified 집계", {s.name: s.verified for s in st}["web-header"] == 1)
check("승인 부담 필드 존재(기본 0)", all(r.approvals_needed == 0 for r in res))
d = B.to_dict("x", 1, "none", st, res)
check("JSON totals 에 verified_solve_rate·verified_any",
      "verified_solve_rate" in d["totals"] and "verified_any" in d["totals"])
check("표에 '검증된 풀이율'", "검증된 풀이율" in B.render(st, 1, "none"))

print("\n=== 사람 관찰 입력(선택) — 건너뛴 명령 대신 직접 확인 내용 기록 ===")
# 범위 밖 명령을 거부(reject-scope)하는 승인자 + 관찰 콜백 주입
def deny(cmd, vrep, sres):     # 정찰(nmap)은 통과, 열거 명령만 거부 → 관찰 입력 경로
    return cmd.startswith("nmap")
def observer(cmd):
    return "브라우저에서 /admin 페이지에 로그인 폼 확인"
g4 = ScopeGuard.from_cidr_strings(); g4.bind_target(T)
kb4 = KnowledgeBase(rules=[Rule(name="w", phase="enum", ports=[80],
                               suggest=["curl -i http://{t}/admin"])], notes=[])
def runweb(c):
    if c.startswith("nmap"):
        return RunOutput(c, stdout=XMLw)
    return RunOutput(c, stdout="ok")
rep4 = Orchestrator(g4, FakeRunner(runweb), kb4, deny, observer=observer,
                    is_tool_available=lambda b: True, max_sweeps=1).run()
obs = [f for f in rep4.enum_findings if "사람 관찰" in (f.note or "")]
check("관찰 입력이 finding 에 기록", obs and "[사람 관찰]" in obs[0].output)
check("관찰이 월드 수집물에 '사람 관찰' 출처로", rep4.world is not None
      and any("사람 관찰" in rep4.world.evidence.get(l, "") for l in rep4.world.loot))
check("관찰 명령은 실행되지 않음(ran=False)", obs and not obs[0].ran)
# observer 가 빈 문자열이면 아무것도 기록 안 함
rep5 = Orchestrator(g4, FakeRunner(runweb), kb4, deny, observer=lambda c: "",
                    is_tool_available=lambda b: True, max_sweeps=1).run()
check("빈 관찰은 기록 안 함", not any("사람 관찰" in (f.note or "") for f in rep5.enum_findings))
# observer 없으면 기존 동작(관찰 없음)
rep6 = Orchestrator(g4, FakeRunner(runweb), kb4, deny,
                    is_tool_available=lambda b: True, max_sweeps=1).run()
check("observer 미지정 → 관찰 없음(기존 동작)", not any("사람 관찰" in (f.note or "")
                                                   for f in rep6.enum_findings))
a2 = M.build_parser().parse_args([T, "--observe"])
check("파서: --observe", a2.observe is True)

print("\n=== HTTP 요약기: 본문 단서 보존(경로·링크·주석) ===")
from htb_agent.observation.parsers import parse_http  # noqa: E402
h = parse_http("HTTP/1.1 200 OK\nServer: Apache\n\n<html><!-- old: /backup.zip -->"
               "<a href=\"/login.php\">in</a><a href=\"https://cdn.example/x.js\">ext</a>"
               "<script src=\"//cdn.example/y.js\"></script> see /security.txt</html>")
check("주석 단서", any(c.startswith("주석:") and "/backup.zip" in c for c in h.clues))
check("내부 링크 단서", "/login.php" in h.clues)
check("평문 경로 단서", "/security.txt" in h.clues)
check("외부·프로토콜 상대 링크 제외", not any("cdn.example" in c for c in h.clues))
check("요약에 '단서=' 포함", "단서=" in h.summary())
many = parse_http("HTTP/1.1 200 OK\n\n" + " ".join(f"/p{i}" for i in range(20)))
check("단서는 최대 5개", len(many.clues) == 5)
check("본문 없으면 단서 없음", parse_http("HTTP/1.1 204 No Content\n\n").clues == [])

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
