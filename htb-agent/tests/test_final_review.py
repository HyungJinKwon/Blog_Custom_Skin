# 실행: htb-agent 디렉토리에서  python3 tests/test_final_review.py
# 최종 마무리 검수(2026-10)에서 재현 확인한 결함 회귀 테스트.
#   MED-1: 자율학습 결과가 world.loot 를 오염시켜 lateral 전제조건을 거짓 충족.
#   MED-2: provenance verdict 가 --resume 시 재계산(약화)되어 정직성 표시 상실/goal 뒤집힘.
#   품질 : 첫 포트스캔 중 Ctrl+C 가 raw 트레이스백 + 상태 유실로 이어짐(--resume 약속 위반).
import sys
import tempfile
sys.path.insert(0, "src")
from htb_agent.world import WorldModel  # noqa: E402
from htb_agent.scope_guard import ScopeGuard  # noqa: E402
from htb_agent.knowledge import KnowledgeBase  # noqa: E402
from htb_agent.state import SessionState, StateStore  # noqa: E402
from htb_agent.orchestrator import Orchestrator, OrchestrationReport  # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput  # noqa: E402
from htb_agent.tools.recon import auto_approve_in_scope  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

def guard():
    g = ScopeGuard.from_cidr_strings(); g.bind_target("10.129.1.5"); return g

def orc(**kw):
    return Orchestrator(guard(), FakeRunner(lambda c: RunOutput(c, stdout="ok")),
                        KnowledgeBase.load(), auto_approve_in_scope, **kw)

print("=== MED-1. 자율학습 지식은 loot 과 분리 — lateral 전제를 충족시키지 않음 ===")
w = WorldModel(target="10.129.1.5")
w.add_learned("자율학습: kerberoasting")
check("learned 에 적재", "자율학습: kerberoasting" in w.learned)
check("loot 는 오염되지 않음", w.loot == [])
check("learned 지식이 LLM 컨텍스트에 노출", any("학습한 지식" in ln for ln in w.context_lines()))

o = orc()
o.world = w   # 자격증명·foothold 없음, 학습 지식만 있음
met, _ = o._prereq_met("lateral")
check("학습만 있을 때 lateral 전제 미충족(투기 라운드 억제)", met is False)
w.add_loot("해시: aad3b4...")   # 실제 수집물이 생기면
met2, _ = o._prereq_met("lateral")
check("실제 loot(해시) 생기면 lateral 전제 충족", met2 is True)

print("\n=== MED-2. provenance verdict 는 persist→restore 에서 보존(재계산 금지) ===")
with tempfile.TemporaryDirectory() as d:
    store = StateStore(d)
    # looked-up(라이트업·학습 유래 의심) 플래그가 저장됐다가 재개되는 상황
    prior = SessionState(target="10.129.1.5", flags=[
        {"value": "HTB{x}", "kind": "root", "source": "cat notes.md",
         "verdict": "looked-up", "prov_command": "", "phase": "enum",
         "reason": "외부/학습 자료에 같은 값 존재"},
        # 오프라인 첨부에서 공략으로 얻은 플래그(재계산하면 local-derived 로 떨어짐)
        {"value": "HTB{y}", "kind": "user", "source": "cat files/flag.txt",
         "verdict": "exploit-derived", "prov_command": "cat files/flag.txt",
         "phase": "enum", "reason": "첨부파일 분석 출력"},
    ])
    o2 = orc(state_store=store)
    rep = OrchestrationReport(target="10.129.1.5")
    o2.world = WorldModel(target="10.129.1.5")
    o2._restore(rep, prior, set())
    vd = {p.value: p.verdict for p in rep.flag_provenance}
    check("looked-up 보존(exploit-derived 로 승격 안 됨)", vd.get("HTB{x}") == "looked-up")
    check("exploit-derived 보존(local-derived 로 강등 안 됨)", vd.get("HTB{y}") == "exploit-derived")

    # persist 가 verdict 를 저장하는지(왕복) — report 의 provenance 를 다시 저장해 확인
    o2._persist(rep, prior)
    saved = {f["value"]: f.get("verdict") for f in store.load("10.129.1.5").flags}
    check("persist 가 verdict 를 기록", saved.get("HTB{x}") == "looked-up"
          and saved.get("HTB{y}") == "exploit-derived")

    # 구버전 상태(verdict 미저장)는 보수적 재계산으로 호환
    old = SessionState(target="10.129.1.5", flags=[
        {"value": "HTB{z}", "kind": "root", "source": "nmap -sV 10.129.1.5"}])
    o3 = orc(); o3.world = WorldModel(target="10.129.1.5")
    rep3 = OrchestrationReport(target="10.129.1.5")
    o3._restore(rep3, old, set())
    check("verdict 없는 구상태는 재계산으로 호환(크래시 없음)",
          len(rep3.flag_provenance) == 1 and rep3.flag_provenance[0].verdict)

print("\n=== 품질. 첫 포트스캔 중 Ctrl+C → 트레이스백 없이 상태 저장(--resume 가능) ===")
def interrupt_on_nmap(cmd):
    if cmd.startswith("nmap"):
        raise KeyboardInterrupt
    return RunOutput(cmd, stdout="ok")
with tempfile.TemporaryDirectory() as d:
    store = StateStore(d)
    oi = Orchestrator(guard(), FakeRunner(interrupt_on_nmap), KnowledgeBase.load(),
                      auto_approve_in_scope, state_store=store)
    try:
        rep = oi.run()
        raised = False
    except KeyboardInterrupt:
        raised = True
    check("정찰 중 Ctrl+C 가 밖으로 전파되지 않음", raised is False)
    check("상태 interrupted 로 정상 종료", rep.status == "interrupted")
    check("중단 상태 저장됨(--resume 로 이어감)", store.exists("10.129.1.5"))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
