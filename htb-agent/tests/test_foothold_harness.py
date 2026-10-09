# 실행: htb-agent 디렉토리에서  python3 tests/test_foothold_harness.py
#
# FakeFoothold 테스트 하네스 — exploit-exec 실행 엔진(설계안 참고)을 '실 타겟 없이'
# 검증하기 위한 복붙용 템플릿. 실제 Foothold(SSH/리버스쉘/웹RCE)를 구현할 때, 이
# FakeFoothold 를 주입해 "발판→플래그 읽기→provenance→SOLVED" 루프를 결정적으로
# 테스트한다. 여기서는 '이미 존재하는' 플래그 캡처·출처 검증·SOLVED 화면만 검증하므로
# 안전하며, exploit-exec 본체가 저장소에 들어오면 그 루프에 그대로 끼워 쓰면 된다.
import sys
sys.path.insert(0, "src")
from htb_agent.flag import scan as scan_flags  # noqa: E402
from htb_agent import provenance as prov  # noqa: E402
from htb_agent.orchestrator import OrchestrationReport  # noqa: E402
from htb_agent.flag import FlagHit  # noqa: E402
from htb_agent.report_view import render_solved  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")


class FakeFoothold:
    """타겟 명령 실행 채널의 테스트 더블. 실제 SSH/리버스쉘 대신, cmd 부분문자열 →
    가짜 출력 매핑으로 결정적 응답을 돌려준다. 실행 엔진의 run() 자리에 그대로 주입.
      scenario: {cmd 에 포함될 부분문자열: 반환 stdout}
    """
    kind = "fake"

    def __init__(self, scenario: dict[str, str], user: str = "svc"):
        self.scenario = scenario
        self.user = user
        self.ran: list[str] = []

    def run(self, cmd: str, timeout: int = 60):
        self.ran.append(cmd)
        for needle, out in self.scenario.items():
            if needle in cmd:
                return out
        return ""

    def alive(self) -> bool:
        return True

    def close(self) -> None:
        pass


# 실행 엔진이 할 '발판→플래그' 루프의 핵심 로직만 추려 테스트(엔진 본체 없이도 검증 가능).
def capture_flags_via_foothold(report, foothold, reads):
    """foothold 로 read 명령을 실행하고, 출력에서 플래그를 캡처해 report 에 반영한다.
    실제 엔진에서는 orchestrator._attempt 가 이 역할을 하며(게이트+_process), 여기서는
    그 '캡처+provenance' 부분만 떼어 재현한다."""
    for cmd in reads:
        out = foothold.run(cmd)
        for hit in scan_flags(cmd, out, flag_kind=report.flag_kind):
            if hit.value not in {f.value for f in report.flags}:
                report.flags.append(hit)
                report.flag_provenance.append(prov.classify(hit.kind, hit.value, cmd))


print("=== FakeFoothold: 발판 → user/root 플래그 캡처 ===")
fh = FakeFoothold({
    "user.txt": "HTB{user_flag_aaaa}\n",
    "root.txt": "HTB{root_flag_bbbb}\n",
    "id": "uid=0(root) gid=0(root)",
})
rep = OrchestrationReport(target="10.129.1.5", flag_kind="boot2root")
# 실제 엔진이 실행하는 형태(ssh 래핑) — provenance 가 ssh 를 '공략 유래'로 분류한다.
capture_flags_via_foothold(rep, fh, [
    "sshpass -p pw ssh svc@10.129.1.5 'cat /home/svc/user.txt'",   # → user
    "sshpass -p pw ssh svc@10.129.1.5 'cat /root/root.txt'",       # → root
])
check("user 플래그 캡처", rep.user_flag == "HTB{user_flag_aaaa}")
check("root 플래그 캡처", rep.root_flag == "HTB{root_flag_bbbb}")
check("둘 다 exploit-derived(공략 유래)",
      all(p.verdict == "exploit-derived" for p in rep.flag_provenance))
check("foothold.run 이 실제 호출됨", any("user.txt" in c for c in fh.ran))

print("\n=== 분리 명령이어야 user/root 가 정확히 분류됨(회귀 가드) ===")
# 한 명령에 user.txt+root.txt 를 섞으면 scan 이 'root' 로 몰아 분류 → 분리 필요(설계 반영).
mixed = scan_flags("cat /root/root.txt; cat /home/x/user.txt",
                   "HTB{a}\nHTB{b}\n", flag_kind="boot2root")
check("혼합 명령은 kind 가 섞여 분리 필요함을 확인", {h.kind for h in mixed} == {"root"})

print("\n=== SOLVED 결과화면 연동 ===")
panel = render_solved(rep)
check("SOLVED 패널에 값 표시", panel and "HTB{user_flag_aaaa}" in panel and "HTB{root_flag_bbbb}" in panel)

print("\n=== single(jeopardy) 시나리오 ===")
fh2 = FakeFoothold({"get_flag": "flag{single_ctf}\n"})
rep2 = OrchestrationReport(target="chall", flag_kind="single")
capture_flags_via_foothold(rep2, fh2, ["./get_flag"])
check("single 플래그 캡처", rep2.flags and rep2.flags[0].value == "flag{single_ctf}")
check("single SOLVED 값 표시", "flag{single_ctf}" in (render_solved(rep2) or ""))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
