# 실행: htb-agent 디렉토리에서  python3 tests/test_bench_replay.py
# 평가 하네스(--bench) · 실행 기록 재생(--replay) · LLM 비용 상한(--max-cost).
import contextlib
import io
import json
import os
import sys
import tempfile
sys.path.insert(0, "src")
from htb_agent import bench as B
from htb_agent import replay as R
from htb_agent import main as M
from htb_agent.knowledge import KnowledgeBase
from htb_agent.llm.base import LLMResponse
from htb_agent.llm.fake_provider import FakeProvider
from htb_agent.llm.router import LLMRouter, HybridRouter
from htb_agent.orchestrator import Orchestrator
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.runner import FakeRunner, RunOutput
from htb_agent.tools.recon import auto_approve_in_scope

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

KB = KnowledgeBase.load("knowledge")
SUITE = B.load_suite(B.default_suite_dir())

print("=== 문제 세트 로드·검증 ===")
check("번들 문제 6개 + 난이도 정렬(easy 먼저, hard 마지막)", len(SUITE) == 6
      and SUITE[0].difficulty == "easy" and SUITE[-1].difficulty == "hard")
check("모든 문제에 플래그·포트", all(c.flag.startswith("FLAG{") and c.ports for c in SUITE))
with tempfile.TemporaryDirectory() as d:
    with open(os.path.join(d, "bad.json"), "w", encoding="utf-8") as f:
        json.dump({"name": "x"}, f)
    try:
        B.load_suite(d); check("필수 키 없으면 거부", False)
    except B.BenchError as e:
        check("필수 키 없으면 거부", "필수 키" in str(e))
try:
    B.load_suite("/nonexistent/dir"); check("없는 경로 거부", False)
except B.BenchError:
    check("없는 경로 거부", True)

print("\n=== 기준선(규칙만): 쉬움은 풀고 추론 필요 문제는 못 품 ===")
res = B.run_bench(SUITE, attempts=2, kb=KB)
st = {s.name: s for s in B.summarize(SUITE, res)}
check("쉬운 문제 2개 모두 성공", st["web-header"].pass_at_k and st["web-robots"].pass_at_k)
check("중간/어려움 문제는 규칙만으론 실패", not any(st[n].pass_at_k for n in
      ("web-hidden-path", "ftp-anon-file", "redis-key", "web-version-cve")))
check("시도 수 = 문제×2", len(res) == 12)
check("플래그까지 단계 기록", st["web-header"].avg_steps_to_flag == 1.0)
t = B.totals(list(st.values()))
check("집계: 2/6, 난이도별", t["solved_any"] == 2 and t["by_difficulty"]["easy"] == {"solved": 2, "total": 2})

print("\n=== LLM 이 단서를 따라가면 중간 문제도 풀림(가짜 LLM) ===")
def follower(system, user, tier):
    if "분석가" in system:
        return "가설:\n  H1 [우선:상] 단서 따라가기\n확신도: 중"
    hints = []
    if "staff-notes" in user: hints.append("curl -s http://{t}/staff-notes/")
    if "note.txt" in user: hints.append("curl -s ftp://{t}/note.txt --user anonymous:anonymous")
    if "session:42" in user: hints.append("redis-cli -h {t} get flag")
    if "security.txt" in user: hints.append("curl -s http://{t}/security.txt")
    return "\n".join(hints)
router = LLMRouter(FakeProvider(follower))
res2 = B.run_bench(SUITE, attempts=1, kb=KB, router=router)
st2 = {s.name: s for s in B.summarize(SUITE, res2)}
check("LLM 사용 시 6/6 해결(요약기가 본문 단서 보존 → hard 도 해결)",
      sum(s.pass_at_k for s in st2.values()) == 6 and st2["web-version-cve"].pass_at_k)
check("시도별 LLM 호출 수 기록", any(r.llm_calls > 0 for r in res2))
txt = B.render(list(st2.values()), 1, "fake")
check("표: 풀린 문제·난이도별", "풀린 문제" in txt and "medium 3/3" in txt)

print("\n=== 시도별 감사 로그 → 재생 HTML ===")
with tempfile.TemporaryDirectory() as d:
    r1 = B.run_bench(SUITE[:1], attempts=1, kb=KB, trace_dir=d)
    trace = r1[0].trace
    check("시도별 감사 로그 생성", trace and os.path.isfile(trace))
    out, n = R.replay_file(trace)
    html = open(out, encoding="utf-8").read()
    check("재생 HTML 생성 + 단계 있음", n >= 3 and html.startswith("<!doctype html>"))
    steps = R.build_steps(R.load_events(trace))
    cmd = [s for s in steps if s["type"] == "command"]
    check("명령 단계: 제안+결과가 한 단계로", cmd and cmd[0]["status"] == "실행됨")
    check("플래그 단계 포함", any(s["label"] == "플래그 획득" for s in steps))

print("\n=== 재생: 신뢰하지 않는 로그 내용 이스케이프 ===")
with tempfile.TemporaryDirectory() as d:
    p = os.path.join(d, "x.jsonl")
    with open(p, "w", encoding="utf-8") as f:
        f.write(json.dumps({"ts": "1", "event": "proposed", "cmd": "a</script><b>"}) + "\n")
        f.write("broken line\n")
        f.write(json.dumps({"ts": "2", "event": "executed", "cmd": "a</script><b>",
                            "launched": True, "returncode": 0, "summary": "<!-- & -->"}) + "\n")
    out, n = R.replay_file(p)
    h = open(out, encoding="utf-8").read()
    data = h.split('<script id="data" type="application/json">', 1)[1].split("</script>", 1)[0]
    check("깨진 줄은 건너뜀(1단계)", n == 1)
    check("데이터 블록에 '</script>'·'<' 원문 없음", "</script>" not in data and "<" not in data)
    check("디코드하면 원문 복원", json.loads(data)[0]["cmd"] == "a</script><b>")

print("\n=== LLM 비용 상한 ===")
XML = ('<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.129.1.5"/>'
       '<ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/>'
       '</port></ports></host></nmaprun>')
def runner(c):
    return RunOutput(c, stdout=XML if c.startswith("nmap") else "ok")
def pricey(system, user, tier):   # 호출마다 비싼 모델 사용량
    return LLMResponse("curl -s http://{t}/p%d" % len(user) if "분석가" not in system else "가설: x\n확신도: 중",
                       "claude-opus-5-5", prompt_tokens=200000, completion_tokens=50000)
def orch(router, **kw):
    g = ScopeGuard.from_cidr_strings(); g.bind_target("10.129.1.5")
    return Orchestrator(g, FakeRunner(runner), KnowledgeBase(rules=[], notes=[]),
                        auto_approve_in_scope, llm_router=router,
                        is_tool_available=lambda b: True, max_sweeps=2, **kw)
r_cap = LLMRouter(FakeProvider(pricey))
rep = orch(r_cap, max_cost=0.01).run()
check("상한 도달 → cost_capped + 안내", rep.cost_capped and "비용 상한" in rep.message)
calls_capped = r_cap.calls
r_free = LLMRouter(FakeProvider(pricey))
rep2 = orch(r_free).run()
check("상한 없으면 더 많이 호출", r_free.calls > calls_capped and not rep2.cost_capped)
check("상한 후에도 실행은 정상 종료(done)", rep.status == "done")
h = HybridRouter(local=LLMRouter(FakeProvider(pricey)), strong=LLMRouter(FakeProvider(pricey)))
h.suggest_commands({"phase": "x"}, "10.129.1.5")
check("HybridRouter.total_cost = 두 백엔드 합", h.total_cost > 0
      and abs(h.total_cost - (h.local.total_cost + h.strong.total_cost)) < 1e-9)

print("\n=== CLI: --bench / --replay / --max-cost ===")
a = M.build_parser().parse_args(["10.129.1.5", "--max-cost", "2.5"])
check("파서: --max-cost 2.5", a.max_cost == 2.5)
with tempfile.TemporaryDirectory() as d:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        rc = M.main(["--bench", "--attempts", "1", "--state-dir", d])
    out = buf.getvalue()
    runs = os.listdir(os.path.join(d, "bench"))
    check("--bench 정상 종료 + 결과 JSON", rc == 0 and runs
          and os.path.isfile(os.path.join(d, "bench", runs[0], "results.json")))
    check("--bench 출력에 표·재생 안내", "풀린 문제" in out and "--replay" in out)
    tr = os.path.join(d, "bench", runs[0], "web-header_1.jsonl")
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        rc = M.main(["--replay", tr])
    check("--replay 정상 + html 생성", rc == 0 and os.path.isfile(tr[:-6] + ".html"))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        rc = M.main(["--bench", "/nonexistent"])
    check("--bench 잘못된 경로 → 2", rc == 2)
rc, err = None, io.StringIO()
with contextlib.redirect_stdout(err), contextlib.redirect_stderr(err):
    try:
        M.main(["--bench", "--replay", "x.jsonl"])
    except SystemExit as e:
        rc = e.code
check("단독 명령 동시 사용 거부", rc == 2)

print("\n=== 논문 반영: 최근 실패 진단이 분석·명령 맥락에 되먹임 ===")
from htb_agent.knowledge import Rule  # noqa: E402
seen_prompts = []
def watcher(system, user, tier):
    seen_prompts.append(("A" if "분석가" in system else "C", user))
    return "가설: x\n확신도: 중" if "분석가" in system else ""
def r404(c):
    if c.startswith("nmap"):
        return RunOutput(c, stdout=XML)
    return RunOutput(c, stdout="HTTP/1.1 404 Not Found\n\nnot found", returncode=0)
g = ScopeGuard.from_cidr_strings(); g.bind_target("10.129.1.5")
kb404 = KnowledgeBase(rules=[Rule(name="w", phase="enum", ports=[80],
                                  suggest=["curl -i http://{t}/admin"])], notes=[])
rep = Orchestrator(g, FakeRunner(r404), kb404, auto_approve_in_scope,
                   llm_router=LLMRouter(FakeProvider(watcher)),
                   is_tool_available=lambda b: True, max_sweeps=1).run()
check("진단 기록됨(404)", any(d.category.startswith("http-404") for _, d in rep.blockers))
late = [u for k, u in seen_prompts]
check("명령 생성 맥락에 '최근 실패' 포함", any("최근 실패" in u and "404" in u for k, u in seen_prompts if k == "C"))
check("분석가 맥락에 실패 분류 지시 포함", any("틀린 경로 / 실행 문제 / 전제 부족" in u
                                         for k, u in seen_prompts if k == "A"))
fc = Orchestrator._failure_context(rep)
check("대상 응답은 '경로 판단 근거'로 표시", fc and "경로 판단 근거" in fc[0])

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
