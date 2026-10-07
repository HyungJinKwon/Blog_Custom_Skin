# 실행: htb-agent 디렉토리에서  python3 tests/test_promote.py
# 학습 노트 → 번들 시드 승격(검토 후 공유). 관문·병합 규칙 + 커밋된 시드의 CI 불변식.
import contextlib
import glob
import io
import os
import shutil
import sys
import tempfile
sys.path.insert(0, "src")
from htb_agent import promote as P  # noqa: E402
from htb_agent.knowledge import NOTE_CHARS  # noqa: E402
from htb_agent.main import main  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

SEED_DIR = "knowledge/notes/learned"
REQ = ("## 개요", "## 핵심 기법", "## 표준 도구", "## 블루팀 탐지", "## 완화")
LONG = "Structured reference text describing the concept, its mechanics and typical defenses. " * 3

def entry(title, url, summary):
    return f"## {title}\n- 출처: {url}\n" + (f"- 요약: {summary}\n" if summary is not None else "") + "\n"

def workspace(learned_text):
    d = tempfile.mkdtemp()
    shutil.copy(os.path.join(SEED_DIR, "seed-sqli.md"), d)
    with open(os.path.join(d, "learned-sqli.md"), "w", encoding="utf-8") as f:
        f.write("# 학습 노트: sqli (권위 출처)\n\n" + learned_text)
    return d

def read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()

print("=== 관문(check_candidate) ===")
C = P.Candidate
def why(c):   # 거부 사유(통과면 "") — 관문이 꺼져도 TypeError 대신 깔끔히 실패하도록
    return P.check_candidate(c) or ""
check("정상 항목 통과", P.check_candidate(C("A", "https://owasp.org/x", LONG)) is None)
check("허용 출처 아님 → 거부", "허용" in why(C("A", "https://blog.example.com/x", LONG)))
check("URL 없음 → 거부", P.check_candidate(C("A", "", LONG)) is not None)
check("요약 없음 → 거부", "요약 없음" in why(C("A", "https://owasp.org/x", "")))
check("요약 짧음 → 거부", "짧음" in why(C("A", "https://owasp.org/x", "short text")))
check("웹페이지 군더더기 → 거부",
      "군더더기" in why(C("A", "https://owasp.org/x", "Please enable JavaScript. " + LONG)))
check("라이트업 신호 → 거부",
      "라이트업" in why(C("Box HTB writeup walkthrough", "https://owasp.org/x", LONG)))
check("제어문자 → 거부", "제어문자" in why(C("A", "https://owasp.org/x", LONG + "\x00")))

print("\n=== 승격: 통과 항목만 전용 섹션에, 본문 보존 ===")
d = workspace(entry("Good One", "https://owasp.org/a", LONG)
              + entry("Bad Domain", "https://blog.example.com/b", LONG)
              + entry("Short", "https://owasp.org/c", "tiny")
              + entry("Pointer Only", "https://owasp.org/d", None))
orig = read(os.path.join(d, "seed-sqli.md"))
r = P.promote("sqli", d, d, today="2026-10-07")
new = read(os.path.join(d, "seed-sqli.md"))
check("통과 1건 · 거부 3건", len(r.accepted) == 1 and len(r.rejected) == 3 and r.changed)
check("거부 사유 기록", {t for t, _ in r.rejected} == {"Bad Domain", "Short", "Pointer Only"})
check("사람이 쓴 본문은 그대로(앞부분 동일)", new.startswith(orig.rstrip()))
check("승격 섹션 추가", P.PROMOTED_HEADER in new and "### Good One" in new and "2026-10-07" in new)
check("거부 항목은 시드에 없음", "blog.example.com" not in new and "Short" not in new.split(P.PROMOTED_HEADER)[1])
check("필수 섹션 유지", all(s in new for s in REQ))

print("\n=== 멱등·교체·상한 ===")
r2 = P.promote("sqli", d, d, today="2026-10-07")
check("같은 입력 재실행 → 변경 없음", r2.changed is False and read(os.path.join(d, "seed-sqli.md")) == new)
with open(os.path.join(d, "learned-sqli.md"), "w", encoding="utf-8") as f:
    f.write(entry("Good One v2", "https://owasp.org/a", "Updated " + LONG))
P.promote("sqli", d, d, today="2026-10-08")
t = read(os.path.join(d, "seed-sqli.md"))
check("같은 URL 은 새 내용으로 교체(중복 없음)", t.count("https://owasp.org/a") == 1 and "Good One v2" in t)
with open(os.path.join(d, "learned-sqli.md"), "w", encoding="utf-8") as f:
    f.write("".join(entry(f"E{i}", f"https://owasp.org/e{i}", LONG) for i in range(5)))
P.promote("sqli", d, d, today="2026-10-09")
_, ents = P.split_seed(read(os.path.join(d, "seed-sqli.md")))
check(f"주제당 상한 {P.MAX_ENTRIES}건 유지", len(ents) == P.MAX_ENTRIES)
check("최신 승격분이 우선", ents[0].title == "E0")
d2 = workspace(entry("Huge", "https://owasp.org/h", "word " * 400))
P.promote("sqli", d2, d2)
_, e2 = P.split_seed(read(os.path.join(d2, "seed-sqli.md")))
check(f"요약 길이 상한 {P.MAX_SUMMARY}자", len(e2[0].summary) <= P.MAX_SUMMARY)

print("\n=== 오류 처리 ===")
check("지원 주제 아님", P.promote("no-such-topic", d, d).error != "")
empty = tempfile.mkdtemp()
shutil.copy(os.path.join(SEED_DIR, "seed-sqli.md"), empty)
check("학습 노트 없음 → 안내", "학습 노트 없음" in P.promote("sqli", empty, empty).error)
check("promote_all 은 학습 노트 있는 주제만", [x.topic for x in P.promote_all(d, d)] == ["sqli"])
w3 = workspace(entry("Bad", "https://blog.example.com/x", LONG))   # 실제 시드는 절대 쓰지 않음
before3 = read(os.path.join(w3, "seed-sqli.md"))
r3 = P.promote("sqli", w3, w3)
check("통과 항목이 없으면 시드를 쓰지 않음",
      r3.changed is False and read(os.path.join(w3, "seed-sqli.md")) == before3)

print("\n=== CLI: --promote ===")
k = tempfile.mkdtemp()
os.makedirs(os.path.join(k, "notes", "learned"))
shutil.copy(os.path.join(SEED_DIR, "seed-sqli.md"), os.path.join(k, "notes", "learned"))
with open(os.path.join(k, "notes", "learned", "learned-sqli.md"), "w", encoding="utf-8") as f:
    f.write(entry("Good", "https://owasp.org/g", LONG))
out = io.StringIO()
with contextlib.redirect_stdout(out):
    rc = main(["--promote", "sqli", "--knowledge", k])
check("rc 0 + 승격 보고", rc == 0 and "승격 1건" in out.getvalue())
check("검토·커밋 안내 출력", "git diff" in out.getvalue())
with contextlib.redirect_stdout(io.StringIO()):
    check("학습 노트 없으면 rc 2", main(["--promote", "all", "--knowledge", tempfile.mkdtemp()]) == 2)

print("\n=== CI 불변식: 커밋된 시드의 승격 섹션도 관문 통과 ===")
bad, over, long_ = [], [], []
for p in sorted(glob.glob(os.path.join(SEED_DIR, "seed-*.md"))):
    txt = read(p)
    _, es = P.split_seed(txt)
    if len(es) > P.MAX_ENTRIES:
        over.append(os.path.basename(p))
    bad += [(os.path.basename(p), e.title, P.check_candidate(e)) for e in es if P.check_candidate(e)]
    if len(txt) > NOTE_CHARS:
        long_.append(os.path.basename(p))
check(f"승격 항목 전부 관문 통과 (위반: {bad[:3] or '없음'})", not bad)
check(f"주제당 승격 상한 준수 (위반: {over or '없음'})", not over)
check(f"시드 전문이 RAG 반영 상한({NOTE_CHARS}자) 안 (위반: {long_ or '없음'})", not long_)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
