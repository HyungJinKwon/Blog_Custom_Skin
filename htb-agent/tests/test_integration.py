# 실행: htb-agent 디렉토리에서  python3 tests/test_integration.py
# main() 을 러너 주입으로 엔드투엔드 구동 — 전체 파이프라인 통합 검증.
import sys, io, tempfile, os, json
from contextlib import redirect_stdout
sys.path.insert(0, "src")
from htb_agent.main import main
from htb_agent.tools.runner import FakeRunner, RunOutput

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

LINUX = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.129.1.5"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.2 Ubuntu"/></port>
<port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="vsftpd" version="2.3.4"/>
  <script id="vulners" output="CVE-2011-2523"/></port>
</ports></host></nmaprun>"""

def run_main(argv, xml=LINUX):
    r = FakeRunner(lambda c: RunOutput(c, stdout=xml) if c.startswith("nmap") else RunOutput(c, stdout="ok"))
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(argv, runner=r)
    return code, buf.getvalue(), r

print("=== 전체 파이프라인 (main, 러너 주입) ===")
with tempfile.TemporaryDirectory() as d:
    code, out, r = run_main(["10.129.1.5", "--auto", "--state-dir", d])
    check("정상 종료(exit 0)", code == 0)
    check("RECON 수행", "RECON" in out)
    check("PROFILE Linux", "linux" in out.lower())
    check("VULN CVE 탐지", "CVE-2011-2523" in out)
    check("vsftpd 취약점 매핑", "vsftpd" in out.lower())
    check("상태 저장됨", os.path.isfile(os.path.join(d, "10.129.1.5.json")))

print("\n=== 범위밖 타겟 거부 (exit 2) ===")
code, out, r = run_main(["8.8.8.8", "--auto", "--no-save"])
check("범위밖 거부", code == 2)
check("nmap 호출 안 함", not any(c.startswith("nmap") for c in r.calls))

print("\n=== config 파일 경로 ===")
with tempfile.TemporaryDirectory() as d:
    cfg = os.path.join(d, "c.json")
    json.dump({"allowed_ranges": ["10.200.0.0/16"]}, open(cfg, "w"))
    code, out, r = run_main(["10.200.1.1", "--auto", "--no-save", "--config", cfg])
    check("config 허용대역 적용(바인딩 성공)", "10.200.0.0/16" in out)

print("\n=== 재개 (RECON 재사용) ===")
with tempfile.TemporaryDirectory() as d:
    run_main(["10.129.1.5", "--auto", "--state-dir", d])              # 1차 저장
    # 2차: nmap DOWN 반환해도 재스캔 안 함
    r2 = FakeRunner(lambda c: RunOutput(c, stdout="<nmaprun><host><status state='down'/></host></nmaprun>")
                    if c.startswith("nmap") else RunOutput(c, stdout="ok"))
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(["10.129.1.5", "--auto", "--resume", "--state-dir", d], runner=r2)
    out = buf.getvalue()
    check("재개 종료 0", code == 0)
    check("재개 시 nmap 미호출", not any(c.startswith("nmap") for c in r2.calls))
    check("재개 안내 출력", "재개" in out)

print("\n=== 결과 내보내기 플래그 (--writeup / --json / --html, main 경유) ===")
with tempfile.TemporaryDirectory() as d:
    wp = os.path.join(d, "wu.md")
    jp = os.path.join(d, "r.json")
    hp = os.path.join(d, "r.html")
    code, out, r = run_main(["10.129.1.5", "--auto", "--state-dir", d,
                             "--writeup", wp, "--json", jp, "--html", hp])
    check("정상 종료(exit 0)", code == 0)
    check("라이트업 파일 생성", os.path.isfile(wp))
    check("JSON 파일 생성", os.path.isfile(jp))
    check("HTML 파일 생성", os.path.isfile(hp))
    # JSON 은 파싱 가능 + 핵심 필드
    data = json.load(open(jp, encoding="utf-8"))
    check("JSON schema_version", data.get("schema_version") == "1.0")
    check("JSON target 일치", data.get("target") == "10.129.1.5")
    check("JSON CVE 반영", "CVE-2011-2523" in data.get("detected_cve", []))
    # HTML 은 doctype + 타겟 + 이스케이프 건전성
    htmltext = open(hp, encoding="utf-8").read()
    check("HTML doctype", htmltext.startswith("<!doctype html>"))
    check("HTML 타겟 포함", "10.129.1.5" in htmltext)
    # 라이트업에 포트/취약점 반영
    wtext = open(wp, encoding="utf-8").read()
    check("라이트업 CVE 반영", "CVE-2011-2523" in wtext)
    # 안내 메시지(stdout)
    check("내보내기 안내 출력", "JSON 결과 내보내기" in out and "HTML 대시보드" in out)

print("\n=== 기본 경로 내보내기 (--json/--html 경로 생략 → state-dir) ===")
with tempfile.TemporaryDirectory() as d:
    code, out, r = run_main(["10.129.1.5", "--auto", "--state-dir", d, "--json", "--html"])
    check("기본 JSON 경로 생성", os.path.isfile(os.path.join(d, "report_10.129.1.5.json")))
    check("기본 HTML 경로 생성", os.path.isfile(os.path.join(d, "report_10.129.1.5.html")))

print("\n=== 능동적 완전자동 모드 (--autonomous) ===")
with tempfile.TemporaryDirectory() as d:
    # --knowledge 를 임시 디렉토리로 격리 → autonomous 기본활성 자율학습(learn_gaps)이
    # 저장소의 knowledge/ 를 오염시키지 않도록(런타임 learned-*.md 는 임시경로에 기록).
    kd = os.path.join(d, "kb")
    code, out, r = run_main(["10.129.1.5", "--autonomous", "--offline",
                             "--state-dir", d, "--knowledge", kd])
    check("autonomous 정상 종료", code == 0)
    check("autonomous 모드 표기", "autonomous" in out or "능동적 완전자동" in out)
    check("autonomous 에서 enum 실행", any(c.startswith(("curl", "nmap")) for c in r.calls))
    check("autonomous 자율학습 기본 활성 표기", "자율학습" in out)
    # 변형 학습 파일 생성(공격적 기본 max_variants>1 로 변형 시도됨)
    check("변형 학습 영속 파일 생성", os.path.isfile(os.path.join(d, "variant_stats.json")))
# --hackathon 별칭도 동일 동작(저장소 오염 방지 위해 자율학습 끔)
code, out, r = run_main(["10.129.1.5", "--hackathon", "--no-save", "--no-learn-gaps"])
check("--hackathon 별칭 동작", code == 0 and ("autonomous" in out or "능동적 완전자동" in out))
# --manual 은 autonomous 보다 우선(안전) — 범위내여도 대화형 승인 경로
# (FakeRunner 라도 승인 함수가 interactive 면 비대화 입력에서 거부→미실행; 종료는 0)
code, out, r = run_main(["10.129.1.5", "--autonomous", "--manual", "--no-save",
                         "--no-learn-gaps"])
check("--manual 이 autonomous 보다 우선", "완전수동" in out)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
