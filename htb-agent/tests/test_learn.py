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

print("\n=== 완비 불변식: 모든 주제가 번들 시드를 가짐(동일 시작 보장) ===")
# 핵심 설계 불변식 — 모든 사용자가 clone 즉시 '동일하게, 오프라인에서도' 전 주제
# 지식을 갖고 시작한다. 라이브 수집(learn_all)은 그 위의 선택적 보강일 뿐,
# 시작 지식이 환경(네트워크/수집이력)마다 달라지지 않도록 CI 로 강제한다.
_seed_keys = {f[len("seed-"):-3] for f in _os.listdir(seed_dir)
              if f.startswith("seed-") and f.endswith(".md")}
_missing_seed = [t for t in learn.topics() if t not in _seed_keys]
check(f"모든 SOURCES 주제가 seed-<주제>.md 보유 (누락: {_missing_seed or '없음'})",
      not _missing_seed)
# 시드 본문이 실제 KB 노트로 로드되어 RAG 가 참조 가능해야 한다(포인터만이 아님).
_joined_all = " ".join(kb.notes)
check("전 주제 시드가 KB 로 로드됨(학습 시드 헤더 수 ≥ 주제 수)",
      _joined_all.count("학습 시드") >= len(learn.topics()))
# 각 시드는 권위 출처 URL 을 담아야 한다(검증가능성·P1).
_seed_files = [_os.path.join(seed_dir, f) for f in _os.listdir(seed_dir)
               if f.startswith("seed-") and f.endswith(".md")]
_no_src = [p for p in _seed_files
           if not any(dom in open(p, encoding="utf-8").read() for dom in learn.ALLOWED_DOMAINS)]
check(f"모든 시드에 권위 출처 URL 표기 (누락: {[_os.path.basename(p) for p in _no_src] or '없음'})",
      not _no_src)

print("\n=== 완성형 심화 불변식: 종합 레퍼런스 깊이 ===")
# '완성형' 베이스라인 — 각 시드는 짧은 요약이 아니라 종합 레퍼런스여야 한다.
# 섹션(개요·핵심기법·표준명령·블루팀 탐지·완화) + 최소 깊이 + RAG 가 전문을 반영.
_REQUIRED_SECTIONS = ("## 개요", "## 핵심 기법", "## 표준 도구", "## 블루팀 탐지", "## 완화")
_shallow = []
_missing_sec = []
for p in _seed_files:
    txt = open(p, encoding="utf-8").read()
    # 한글은 바이트가 크므로 깊이는 바이트 기준(종합 레퍼런스 ≥ 650B)으로 측정.
    if len(txt.encode("utf-8")) < 650:
        _shallow.append(_os.path.basename(p))
    if not all(sec in txt for sec in _REQUIRED_SECTIONS):
        _missing_sec.append(_os.path.basename(p))
check(f"모든 시드 최소 깊이(≥650B) (미달: {_shallow or '없음'})", not _shallow)
check(f"모든 시드 필수 섹션 구비 (누락: {_missing_sec or '없음'})", not _missing_sec)
# 로더가 500자 병목을 넘어 전문을 반영하는지(심화 지식이 RAG 에 실제 도달)
from htb_agent import knowledge as _kmod
check("노트 반영 상한 상향(병목 해제)", _kmod.NOTE_CHARS >= 4000)
_kb_full = KnowledgeBase.load("knowledge")
_long = [n for n in _kb_full.notes if len(n) > 600]
check("600자 초과 노트가 KB 에 실제 로드됨(심화 반영)", len(_long) >= 20)

print("\n=== learn_all 일괄 사전 학습 ===")
with tempfile.TemporaryDirectory() as d:
    lr = learn.ReferenceLearner(cache_dir=os.path.join(d, "learned"),
                                fetch_fn=lambda u: "<p>doc body</p>", enabled=True)
    results = lr.learn_all()
    check("전체 주제 수만큼 결과", len(results) == len(learn.topics()))
    check("모든 주제 노트 생성(출처 있음)", all(r.refs for r in results))
    check("노트 파일 기록됨", any(os.path.isfile(r.note_path) for r in results if r.note_path))

print("\n=== ingest 사용자 자료 수집 ===")
with tempfile.TemporaryDirectory() as d:
    src = os.path.join(d, "src"); os.makedirs(src)
    with open(os.path.join(src, "writeup.md"), "w") as f:
        f.write("# 내 라이트업\nSMB 널세션 공략")
    with open(os.path.join(src, "notes.txt"), "w") as f:
        f.write("크리덴셜 스프레이 팁")
    with open(os.path.join(src, "ignore.pdf"), "w") as f:
        f.write("binary-ish")
    dest = os.path.join(d, "ingested")
    paths = learn.ingest(src, dest_dir=dest)
    check("md/txt 2개 수집(.pdf 제외)", len(paths) == 2)
    check("원문 보존", any("SMB 널세션" in open(p, encoding="utf-8").read() for p in paths))
    check("수집 헤더 표기", all("수집 자료" in open(p, encoding="utf-8").read() for p in paths))
    # 단일 파일도 허용
    one = learn.ingest(os.path.join(src, "writeup.md"), dest_dir=os.path.join(d, "one"))
    check("단일 파일 수집", len(one) == 1)
    # 자료 없는 경로 → 빈 결과
    check("빈 경로 → 빈 결과", learn.ingest(os.path.join(d, "nope"), dest_dir=dest) == [])

print("\n=== --learn all / --ingest CLI ===")
with tempfile.TemporaryDirectory() as d:
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(["--learn", "all", "--offline", "--knowledge", os.path.join(d, "kb")])
    check("--learn all 종료코드 0", code == 0)
    check("전체 사전 학습 출력", "전체 사전 학습" in buf.getvalue())
    src = os.path.join(d, "mat"); os.makedirs(src)
    with open(os.path.join(src, "a.md"), "w") as f:
        f.write("내 공격 노트")
    buf2 = io.StringIO()
    with redirect_stdout(buf2):
        code2 = main(["--ingest", src, "--knowledge", os.path.join(d, "kb")])
    check("--ingest 종료코드 0", code2 == 0)
    check("수집 완료 출력", "자료 수집 완료" in buf2.getvalue())
a = build_parser().parse_args(["--ingest", "x", "--learn", "all"])
check("--ingest/--learn 파싱", a.ingest == "x" and a.learn == "all" and a.target is None)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
