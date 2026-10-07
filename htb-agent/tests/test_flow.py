# 실행: htb-agent 디렉토리에서  python3 tests/test_flow.py
# 논리 흐름: 목표 달성 조기 종료 · 취약점 즉시 반영 · 분석 갱신 시점 · 예산 의미 ·
#           단계 상태 유지 · 재개 연속성 · 사용자 중단 저장.
import contextlib
import io
import sys
import tempfile
sys.path.insert(0, "src")
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.runner import FakeRunner, RunOutput
from htb_agent.tools.recon import auto_approve_in_scope
from htb_agent.knowledge import KnowledgeBase, Rule
from htb_agent.llm.fake_provider import FakeProvider
from htb_agent.llm.router import LLMRouter
from htb_agent.orchestrator import Orchestrator, OrchestrationReport
from htb_agent.flag import FlagHit
from htb_agent import provenance as prov
from htb_agent.state import StateStore
from htb_agent import main as M

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

T = "10.129.1.5"
XML = f"""<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="{T}"/><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache"/></port>
</ports></host></nmaprun>"""
FLAG = "HTB{" + "a" * 32 + "}"

def out_for(c):
    if c.startswith("nmap -sC"):
        return RunOutput(c, stdout=XML)
    if "whatweb" in c:
        return RunOutput(c, stdout="Server: Apache/2.4.49 — CVE-2021-41773 path traversal")
    if "FLAGCMD" in c:
        return RunOutput(c, stdout="response " + FLAG)
    return RunOutput(c, stdout="ok " + c)

WEB_KB = KnowledgeBase(rules=[Rule(name="web-fp", phase="enum", ports=[80],
                                   suggest=["whatweb http://{t}/", "nikto -h {t}",
                                            "gobuster dir -u http://{t}/"])], notes=[])

def guard():
    g = ScopeGuard.from_cidr_strings(); g.bind_target(T); return g

def orch(runner, llm=None, kb=WEB_KB, **kw):
    kw.setdefault("is_tool_available", lambda b: True)
    return Orchestrator(guard(), runner, kb, auto_approve_in_scope,
                        llm_router=LLMRouter(FakeProvider(llm)) if llm else None, **kw)

print("=== 목표 달성 → 남은 단계 조기 종료(Jeopardy) ===")
def llm_flag(system, user, tier):
    if "분석가" in system:
        return "가설:\n  H1 [우선:상] 웹\n확신도: 중"
    return "curl -s http://{t}/FLAGCMD\ncurl -s http://{t}/after1\ncurl -s http://{t}/after2"
r = FakeRunner(out_for)
rep = orch(r, llm_flag, flag_kind="single", max_sweeps=2).run()
check("플래그 획득", [f.value for f in rep.flags] == [FLAG])
check("플래그 이후 명령은 실행 안 함", not any("after" in c for c in r.calls))
check("남은 단계 = 생략(목표 달성)", rep.phase_status.get("access") == "생략(목표 달성)"
      and rep.phase_status.get("lateral") == "생략(목표 달성)")
check("요약에 목표 달성 표시", "목표 달성" in rep.message and rep.status == "done")

print("\n=== 목표 판정: 신뢰 가능한 플래그만 ===")
def rep_with(kind_flags, flag_kind="boot2root"):
    rp = OrchestrationReport(target=T, flag_kind=flag_kind)
    for kind, value, cmd in kind_flags:
        rp.flags.append(FlagHit(value, kind, cmd))
        rp.flag_provenance.append(prov.classify(kind, value, cmd))
    return rp
o_b2r = orch(FakeRunner(out_for))
o_one = orch(FakeRunner(out_for), flag_kind="single")
o_pref = orch(FakeRunner(out_for), flag_kind="single", flag_prefixes=("DH",))
check("boot2root: user 만 → 계속", not o_b2r._goal_reached(
    rep_with([("user", "a" * 32, "curl http://x/user.txt")])))
check("boot2root: user+root → 종료", o_b2r._goal_reached(rep_with([
    ("user", "a" * 32, "curl http://x/user.txt"), ("root", "b" * 32, "curl http://x/root.txt")])))
check("로컬 명령(cat) 출력의 플래그로는 종료 안 함", not o_one._goal_reached(
    rep_with([("flag", "flag{x}", "cat notes.txt")], "single")))
check("접두 지정 시 다른 접두(미끼)로는 종료 안 함", not o_pref._goal_reached(
    rep_with([("flag", "flag{decoy}", "curl http://x/")], "single")))
check("접두 일치 → 종료", o_pref._goal_reached(
    rep_with([("flag", "DH{real}", "curl http://x/")], "single")))

print("\n=== 취약점이 다음 단계 판단에 즉시 반영 + 분석 갱신 시점 ===")
seen_ctx = []
def llm_ctx(system, user, tier):
    seen_ctx.append(("A" if "분석가" in system else "C", user))
    return "가설:\n  H1 x\n확신도: 중" if "분석가" in system else ""
rep = orch(FakeRunner(out_for), llm_ctx, max_sweeps=1).run()
access_cmd = [u for k, u in seen_ctx if k == "C" and "초기 침투" in u]
check("초기 침투 단계 명령 생성이 '확인 취약점'(CVE)을 봄",
      access_cmd and "확인 취약점" in access_cmd[0] and "CVE-2021-41773" in access_cmd[0])
analyses = [u for k, u in seen_ctx if k == "A"]
check("분석가 2회: 시작 + 열거 결과 반영 후(초기 침투 직전)", len(analyses) == 2)
check("두 번째 분석은 열거 출력을 봄", "whatweb" in analyses[1] and "whatweb" not in analyses[0])

seen_ctx.clear()
orch(FakeRunner(out_for), llm_ctx, kb=KnowledgeBase(rules=[], notes=[]), max_sweeps=1).run()
check("상태 변화 없으면 분석 재호출 안 함(1회)", sum(1 for k, _ in seen_ctx if k == "A") == 1)

print("\n=== 예산: 미설치 도구는 max_enum 을 쓰지 않음 ===")
r = FakeRunner(out_for)
rep = orch(r, max_enum=1, is_tool_available=lambda b: b not in ("whatweb", "nikto")).run()
check("미설치 2개 건너뛰고 설치된 gobuster 실행", any("gobuster" in c for c in r.calls))
check("건너뜀은 skipped 로 표시", sum(f.skipped for f in rep.enum_findings) == 2)
r = FakeRunner(out_for)
rep = orch(r, max_enum=1).run()
check("설치돼 있으면 상한 1 그대로(1개만 실행)", sum(f.ran for f in rep.enum_findings) == 1)

print("\n=== 단계 상태: 한 번 '진행' 이면 다음 스윕에서도 유지 ===")
rep = orch(FakeRunner(out_for), max_sweeps=3).run()
check("enum = 진행(2번째 스윕의 '점검함' 으로 덮이지 않음)", rep.phase_status.get("enum") == "진행")

print("\n=== 재개: 실행한 명령은 다시 돌리지 않고 결과·이력 보존 ===")
with tempfile.TemporaryDirectory() as d:
    st = StateStore(d)
    r1 = FakeRunner(out_for)
    orch(r1, state_store=st, is_tool_available=lambda b: b != "nikto").run()
    r2 = FakeRunner(out_for)
    rep = orch(r2, state_store=st, resume=True).run()
    check("재개: 이미 실행한 whatweb/gobuster 재실행 없음",
          not any("whatweb" in c or "gobuster" in c for c in r2.calls))
    check("재개: 지난번 미설치로 못 한 nikto 는 이번에 실행", any("nikto" in c for c in r2.calls))
    check("재개: 이전 결과 복원(단계 포함)", any(f.command.startswith("whatweb") and f.ran
                                          and f.phase == "enum" for f in rep.enum_findings))
    check("재개: 복원된 출력으로 CVE 재탐지", "CVE-2021-41773" in rep.detected_cve)
    saved = st.load(T)
    cmds = [f["command"] for f in saved.enum_findings]
    check("저장 이력 유실 없음(이전+이번)", any("whatweb" in c for c in cmds)
          and any("nikto" in c for c in cmds))

with tempfile.TemporaryDirectory() as d:
    st = StateStore(d)
    orch(FakeRunner(out_for), llm_flag, flag_kind="single", state_store=st).run()
    r2 = FakeRunner(out_for)
    rep = orch(r2, llm_flag, flag_kind="single", state_store=st, resume=True).run()
    check("재개: 저장된 플래그로 목표 달성 → 대상 상호작용 없음",
          rep.flags and r2.calls == [] and "목표 달성" in rep.message)

print("\n=== 사용자 중단(Ctrl+C): 상태 저장 + 종료코드 130 ===")
def interrupting(c):
    if "nikto" in c:
        raise KeyboardInterrupt
    return out_for(c)
with tempfile.TemporaryDirectory() as d:
    st = StateStore(d)
    rep = orch(FakeRunner(interrupting), state_store=st).run()
    check("status=interrupted + 안내", rep.status == "interrupted" and "--resume" in rep.message)
    check("중단 전 결과 저장", any("whatweb" in f["command"] for f in st.load(T).enum_findings))
    check("중단 전 출력의 CVE 도 반영", "CVE-2021-41773" in rep.detected_cve)
def interrupting_main(c):   # 번들 KB 경로: 웹 열거 중 robots.txt 확인에서 중단
    if "robots.txt" in c:
        raise KeyboardInterrupt
    return out_for(c)
with tempfile.TemporaryDirectory() as d:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        rc = M.main([T, "--auto", "--state-dir", d, "--no-audit", "--offline"],
                    runner=FakeRunner(interrupting_main))
    check("main 종료코드 130", rc == 130)
    check("main 경로도 상태 저장", StateStore(d).exists(T))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
