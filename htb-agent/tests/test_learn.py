# 실행: htb-agent 디렉토리에서  python3 tests/test_learn.py
# 권위 출처 자가학습(Option A, P1 유지) — 허용도메인·주입식 fetcher·오프라인·CLI.
import io
import os
import sys
import tempfile
from contextlib import redirect_stdout
sys.path.insert(0, "src")
from htb_agent import ui, learn
from htb_agent.main import build_parser, main

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

ui.set_color_enabled(False)

print("=== 허용 도메인(allowlist) ===")
check("MITRE 허용", learn.is_allowed("https://attack.mitre.org/techniques/T1558/003/"))
check("portswigger 허용", learn.is_allowed("https://portswigger.net/web-security"))
check("하위도메인 허용", learn.is_allowed("https://cheatsheetseries.owasp.org/x"))
check("임의 도메인 차단", not learn.is_allowed("https://evil.example.com/writeup"))
check("유사도메인 차단", not learn.is_allowed("https://attack.mitre.org.evil.com/"))
check("블로그/라이트업 차단", not learn.is_allowed("https://medium.com/@x/htb-machine-writeup"))

print("\n=== P1 가드: 카탈로그 전 출처가 허용 도메인 ===")
bad = [(k, u) for k, refs in learn.SOURCES.items() for (_, u) in refs if not learn.is_allowed(u)]
check(f"모든 SOURCES 가 권위 도메인 (위반: {bad or '없음'})", not bad)

print("\n=== extract_text: 태그 제거 ===")
txt = learn.extract_text("<html><head><title>t</title></head>"
                         "<body><script>bad()</script><p>Hello &amp; World</p></body></html>")
check("script/style 제거", "bad()" not in txt)
check("태그 제거 + 엔티티 복원", "Hello & World" in txt)

print("\n=== match_sources ===")
check("정확 일치", learn.ReferenceLearner().match_sources("burp"))
check("부분 일치(kerberos→kerberos/kerberoasting)", len(learn.ReferenceLearner().match_sources("kerberos")) >= 1)
check("미지원 주제 빈 결과", learn.ReferenceLearner().match_sources("nonsense-topic-xyz") == [])
check("빈 주제 → 전체매칭 방지", learn.ReferenceLearner().match_sources("") == [])
check("공백 주제 → 전체매칭 방지", learn.ReferenceLearner().match_sources("   ") == [])

print("\n=== learn (주입 fetcher, 온라인 모사) ===")
CANNED = ("<html><body><h1>Kerberoasting</h1><p>Adversaries may abuse a valid "
          "Kerberos ticket-granting ticket.</p><script>x</script></body></html>")
with tempfile.TemporaryDirectory() as d:
    lr = learn.ReferenceLearner(cache_dir=os.path.join(d, "learned"),
                                fetch_fn=lambda url: CANNED, enabled=True)
    res = lr.learn("kerberoasting")
    check("출처 수집", len(res.refs) == 1 and res.refs[0].url.startswith("https://attack.mitre.org"))
    check("본문 요약 추출", "ticket-granting" in res.refs[0].excerpt and "x" not in res.refs[0].excerpt.split()[-1:])
    check("노트 파일 생성", os.path.isfile(res.note_path))
    note = open(res.note_path, encoding="utf-8").read()
    check("노트에 출처 URL", "attack.mitre.org" in note)
    check("노트에 P1 명시", "라이트업 미참조" in note)

print("\n=== learn (오프라인 → 포인터만) ===")
with tempfile.TemporaryDirectory() as d:
    lr = learn.ReferenceLearner(cache_dir=os.path.join(d, "learned"),
                                fetch_fn=lambda url: "SHOULD-NOT-BE-CALLED", enabled=False)
    res = lr.learn("burp")
    check("오프라인: 출처는 있음", len(res.refs) >= 1)
    check("오프라인: 본문 없음", all(not r.excerpt for r in res.refs))

print("\n=== CLI ===")
pp = build_parser()
a = pp.parse_args(["--learn", "sqli"])
check("--learn 파싱(target 선택)", a.learn == "sqli" and a.target is None)
with tempfile.TemporaryDirectory() as d:
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(["--learn", "xss", "--offline", "--knowledge", d])
    check("--learn 종료 0", code == 0)
    check("--learn 출력에 출처", "owasp.org" in buf.getvalue() or "portswigger" in buf.getvalue())
    check("노트 디렉토리에 저장", os.path.isfile(os.path.join(d, "notes", "learned", "learned-xss.md")))
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(["--learn", "list"])
    check("--learn list 종료 0", code == 0 and "kerberoasting" in buf.getvalue())
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(["--learn", "nonsense-xyz", "--offline", "--knowledge", d])
    check("미지원 주제 종료 2", code == 2)

print("\n=== 확장 카탈로그 + 사전 학습 시드 ===")
check("주제 50개 이상", len(learn.SOURCES) >= 50)
for t in ["csrf", "xxe", "jwt", "ssti", "brute-force", "ftp", "ssh", "ssrf"]:
    check(f"신규/주요 주제 존재: {t}", t in learn.SOURCES)
# 사전 심은 시드 노트가 KB(notes)로 로드되는지(성장 반영)
import os as _os
from htb_agent.knowledge import KnowledgeBase
kb = KnowledgeBase.load("knowledge")
joined = " ".join(kb.notes)
check("시드 노트 KB 로드(kerberoasting)", "학습 시드: kerberoasting" in joined or "Kerberoast" in joined)
seed_dir = "knowledge/notes/learned"
check("시드 디렉토리 존재", _os.path.isdir(seed_dir) and len(_os.listdir(seed_dir)) >= 15)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
