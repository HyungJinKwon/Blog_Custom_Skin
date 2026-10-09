# 실행: htb-agent 디렉토리에서  python3 tests/test_fingerprint.py
#
# 웹앱 핑거프린트 → {product}/{version} 치환 검증. 관측 코퍼스(제목·배너·enum 출력)에서
# 제품/버전을 식별해 'searchsploit {product} {version}' 가 'searchsploit freepbx …' 처럼
# 자동 실행 가능한 구체 명령이 되는지 확인(외부 조회 없음 — 텍스트 매칭만, P1 유지).
import sys
sys.path.insert(0, "src")
from htb_agent.vuln import fingerprint_webapp  # noqa: E402
from htb_agent.world import WorldModel  # noqa: E402
from htb_agent.scope_guard import ScopeGuard  # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput  # noqa: E402
from htb_agent.tools.recon import auto_approve_in_scope  # noqa: E402
from htb_agent.knowledge import KnowledgeBase  # noqa: E402
from htb_agent.orchestrator import Orchestrator  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")


print("=== fingerprint_webapp (제품/버전 식별) ===")
# 실제 connected.htb 관측 라인 모사
corpus = ('HTTP 200 OK | Server=Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16 '
          '| title="FreePBX Administration" | forms=로그인폼[POST (self)]')
check("FreePBX 제품 식별", fingerprint_webapp(corpus)[0] == "freepbx")
check("버전 미상이면 빈 문자열", fingerprint_webapp(corpus)[1] == "")
check("FreePBX 버전 추출", fingerprint_webapp("FreePBX 15.0.16.75 running")[1] == "15.0.16.75")
check("WordPress 식별+버전", fingerprint_webapp('<meta name="generator" content="WordPress 6.4.2">')
      == ("wordpress", "6.4.2"))
check("Tomcat 식별", fingerprint_webapp("Apache Tomcat/9.0.54")[0] == "tomcat")
check("웹앱 없음 → 빈값", fingerprint_webapp("HTTP 200 OK | Server=nginx") == ("", ""))
check("빈 입력 안전", fingerprint_webapp("") == ("", ""))

print("\n=== WorldModel.set_web_app ===")
w = WorldModel(target="10.129.245.100")
w.set_web_app("freepbx", "")
check("제품 기록", w.web_product == "freepbx")
check("버전 비어있음 유지", w.web_version == "")
w.set_web_app("freepbx", "15.0")              # 이후 버전 확인되면 보강
check("나중에 버전 보강", w.web_version == "15.0")
w.set_web_app("wordpress", "6.0")             # 다른 제품으로 덮어쓰지 않음(먼저 잡힌 것 유지)
check("제품 덮어쓰기 안 함", w.web_product == "freepbx")

print("\n=== Orchestrator._fill_fingerprint ({product}/{version} 치환) ===")
def guard():
    g = ScopeGuard.from_cidr_strings(); g.bind_target("10.129.245.100"); return g
orc = Orchestrator(guard(), FakeRunner(lambda c: RunOutput(c, stdout="ok")),
                   KnowledgeBase.load(), auto_approve_in_scope,
                   is_tool_available=lambda b: True)
orc.world = WorldModel(target="10.129.245.100")

# 식별 전: placeholder 유지(섣부른 치환 금지 → 수동 제안으로 남음)
tmpl = "searchsploit {product} {version}"
check("식별 전 placeholder 유지", orc._fill_fingerprint(tmpl) == tmpl)

# 제품만 식별(버전 미상): 'searchsploit freepbx' 로 정리({version} 제거)
orc.world.set_web_app("freepbx", "")
check("제품만 → searchsploit freepbx", orc._fill_fingerprint(tmpl) == "searchsploit freepbx")
check("-w 변형도 치환", orc._fill_fingerprint("searchsploit -w {product}") == "searchsploit -w freepbx")

# 버전까지 식별: 'searchsploit freepbx 15.0'
orc.world.set_web_app("freepbx", "15.0")
check("제품+버전 치환", orc._fill_fingerprint(tmpl) == "searchsploit freepbx 15.0")

# nmap 서비스 제품으로 폴백(웹앱 미식별 시)
orc2 = Orchestrator(guard(), FakeRunner(lambda c: RunOutput(c, stdout="ok")),
                    KnowledgeBase.load(), auto_approve_in_scope,
                    is_tool_available=lambda b: True)
orc2.world = WorldModel(target="10.129.245.100")
orc2.world.add_service(80, "tcp", "http", "nginx", "1.18.0")
check("웹앱 미식별 → nmap 제품 폴백",
      orc2._fill_fingerprint("searchsploit {product} {version}") == "searchsploit nginx 1.18.0")

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
