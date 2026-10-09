# 실행: htb-agent 디렉토리에서  python3 tests/test_version_probe.py
#
# ① 버전 노출 능동 프로브 — 제품은 식별됐으나 버전이 미상일 때, 문서화된 버전 노출 경로를
# 무해한 GET(curl -sik)으로 긁어 버전을 집어내는지 검증. 조회·무해(익스 실행 아님)·제품당 1회.
import sys
sys.path.insert(0, "src")
from htb_agent.exploits import probes_for                      # noqa: E402
from htb_agent.scope_guard import ScopeGuard                   # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput       # noqa: E402
from htb_agent.tools.recon import auto_approve_in_scope        # noqa: E402
from htb_agent.knowledge import KnowledgeBase                  # noqa: E402
from htb_agent.orchestrator import Orchestrator, OrchestrationReport  # noqa: E402
from htb_agent.world import WorldModel                         # noqa: E402
from htb_agent.observation.parsers import NmapHost, Port       # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

TARGET = "10.129.245.100"

print("=== probes_for (레지스트리 데이터) ===")
check("freepbx 프로브 존재(버전 노출 GET)", any("admin/config.php" in p for p in probes_for("freepbx")))
check("프로브는 전부 curl 조회 GET(실행/익스 아님)",
      all(p.startswith("curl ") for p in probes_for("freepbx")))
check("프로브에 RCE/셸 토큰 없음(생성 전용 경계)",
      all(not any(t in p for t in ("| sh", "bash -i", "nc -e", ";")) for p in probes_for("freepbx")))
check("{base} 치환", probes_for("freepbx", "https://x")[0].startswith("curl -sik https://x/"))
check("미등록 제품 → 빈 목록", probes_for("nginx") == [])
check("빈/None 안전", probes_for("") == [] and probes_for(None) == [])

print("\n=== _web_bases (열린 웹 포트 → 베이스 URL) ===")
def mk_host(ports):
    h = NmapHost(address=TARGET, state="up")
    h.ports = ports
    return h

def guard():
    g = ScopeGuard.from_cidr_strings(); g.bind_target(TARGET); return g
def mk_orc(runner):
    o = Orchestrator(guard(), runner, KnowledgeBase.load(), auto_approve_in_scope,
                     flag_kind="boot2root", is_tool_available=lambda b: True)
    o._start = o._clock(); o._deadline = None
    o.world = WorldModel(target=TARGET)
    return o

orc0 = mk_orc(FakeRunner(lambda c: RunOutput(c, stdout="")))
https_host = mk_host([Port(443, "tcp", "open", service="https"),
                      Port(80, "tcp", "open", service="http")])
bases = orc0._web_bases(https_host)
check("https 베이스 우선", bases and bases[0] == f"https://{TARGET}")
check("http 베이스도 수집", f"http://{TARGET}" in bases)
check("표준 포트는 포트 생략", all(b in (f"https://{TARGET}", f"http://{TARGET}") for b in bases))
nonstd = orc0._web_bases(mk_host([Port(8443, "tcp", "open", service="https-alt")]))
check("비표준 TLS 포트 명시", nonstd == [f"https://{TARGET}:8443"])
check("웹 아닌 포트는 베이스 없음", orc0._web_bases(mk_host([Port(22, "tcp", "open", service="ssh")])) == [])

print("\n=== _version_probe_stage (게이트 경유 프로브 → 버전 추출) ===")
# FreePBX 버전을 '푸터(본문 깊숙이)'에 둔 HTTP 응답 — 200자 트렁케이트에도 appver 로 살아남아야.
FREEPBX_BODY = ("HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n<html><head><title>FreePBX "
                "Administration</title></head><body>" + ("<div>padding</div>" * 40) +
                "<footer>FreePBX 16.0.40 is licensed under GPL</footer></body></html>")
def fake(cmd):
    if cmd.startswith("curl") and "admin/config.php" in cmd:
        return RunOutput(cmd, stdout=FREEPBX_BODY)
    if cmd.startswith("curl"):
        return RunOutput(cmd, stdout="HTTP/1.1 404 Not Found\r\n\r\nnope")
    return RunOutput(cmd, stdout="")

orc = mk_orc(FakeRunner(fake))
rep = OrchestrationReport(target=TARGET, flag_kind="boot2root")

# 제품 미식별 → 프로브 없음
orc._version_probe_stage(rep, https_host)
check("제품 미식별 → 프로브 없음", not rep.enum_findings)

# 제품 식별(버전 미상) → 프로브 실행 → 버전 추출 → 월드에 반영
orc.world.set_web_app("freepbx", "")
orc._version_probe_stage(rep, https_host)
check("프로브가 게이트 통과·실행됨", any("admin/config.php" in (f.command or "") for f in rep.enum_findings))
check("프로브 출력에서 버전 추출(appver=FreePBX 16.0.40)", orc.world.web_version == "16.0.40")

# 멱등: 버전 확보 후 재호출은 프로브 추가 없음
n = len(rep.enum_findings)
orc._version_probe_stage(rep, https_host)
check("버전 확보 후 재호출 무동작(멱등)", len(rep.enum_findings) == n)

# 버전이 끝내 안 보이면 '미상' 유지 — 섣부른 단정 금지
def fake_noversion(cmd):
    return RunOutput(cmd, stdout="HTTP/1.1 200 OK\r\n\r\n<title>FreePBX Administration</title>login")
orc2 = mk_orc(FakeRunner(fake_noversion))
orc2.world.set_web_app("freepbx", "")
rep2 = OrchestrationReport(target=TARGET, flag_kind="boot2root")
orc2._version_probe_stage(rep2, https_host)
check("버전 미노출이면 미상 유지", orc2.world.web_version == "")
check("미노출이어도 프로브는 1회만(멱등 가드)", "freepbx" in orc2._version_probed)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
