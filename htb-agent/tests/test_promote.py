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
from htb_agent import learn  # noqa: E402
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

# 관문·병합 규칙 시험용 가상 출처를 sqli 카탈로그에 잠시 추가(CI 불변식 전에 원복)
_REAL_SQLI = list(learn.SOURCES["sqli"])
learn.SOURCES["sqli"] = _REAL_SQLI + [(u, u) for u in
    ["https://owasp.org/a", "https://owasp.org/c", "https://owasp.org/d", "https://owasp.org/h",
     "https://owasp.org/g", "https://blog.example.com/b", "https://blog.example.com/x"]
    + [f"https://owasp.org/e{i}" for i in range(5)]]

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
check("사이트 이전 공지 → 거부",
      "군더더기" in why(C("A", "https://owasp.org/x", "Thank you for visiting OWASP.org. We have migrated " + LONG)))
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
check("사람이 쓴 본문은 그대로", P.split_seed(new)[0] == P.split_seed(orig)[0])
check("승격 섹션 추가", P.PROMOTED_HEADER in new and "### Good One" in new and "2026-10-07" in new)
check("거부 항목은 시드에 없음", "blog.example.com" not in new and "### Short" not in new and "### Pointer Only" not in new)
check("필수 섹션 유지", all(s in new for s in REQ))

print("\n=== 멱등·교체·상한 ===")
r2 = P.promote("sqli", d, d, today="2026-10-07")
check("같은 입력 재실행 → 변경 없음", r2.changed is False and read(os.path.join(d, "seed-sqli.md")) == new)
r2b = P.promote("sqli", d, d, today="2026-10-14")
check("다음 주 같은 내용 재실행 → 날짜만 바뀌지 않음(변경 없음)",
      r2b.changed is False and read(os.path.join(d, "seed-sqli.md")) == new)
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

print("\n=== 카탈로그 연동: 빠진 출처는 승격 거부 + 기존 승격분 정리 ===")
d4 = workspace(entry("Good", "https://owasp.org/a", LONG) + entry("Retired", "https://owasp.org/r", LONG))
r4 = P.promote("sqli", d4, d4, today="2026-10-07")
check("카탈로그에 없는 출처 → 거부", [t for t, _ in r4.rejected] == ["Retired"]
      and "카탈로그" in r4.rejected[0][1])
learn.SOURCES["sqli"].append(("x", "https://owasp.org/r"))
P.promote("sqli", d4, d4, today="2026-10-07")          # 카탈로그에 있을 때 승격된 상태를 만든 뒤
learn.SOURCES["sqli"].pop()                              # 카탈로그에서 교체·삭제
with open(os.path.join(d4, "learned-sqli.md"), "w", encoding="utf-8") as f:
    f.write(entry("Good", "https://owasp.org/a", LONG))
before4 = read(os.path.join(d4, "seed-sqli.md"))
r5 = P.promote("sqli", d4, d4, today="2026-10-07")
after4 = read(os.path.join(d4, "seed-sqli.md"))
check("낡은 승격분 정리 기록", [t for t, _ in r5.pruned] == ["Retired"] and r5.changed)
check("정리 후 시드에서 사라지고 나머지는 유지",
      "owasp.org/r" in before4 and "owasp.org/r" not in after4 and "### Good" in after4)
check("정리 후 사람이 쓴 본문 유지", P.split_seed(after4)[0] == P.split_seed(before4)[0])
with open(os.path.join(d4, "learned-sqli.md"), "w", encoding="utf-8") as f:
    f.write(entry("Bad", "https://blog.example.com/x", LONG))
learn.SOURCES["sqli"] = [s for s in learn.SOURCES["sqli"] if s[1] != "https://owasp.org/a"]
r6 = P.promote("sqli", d4, d4)
check("통과 항목이 없어도 정리할 것이 있으면 시드 갱신",
      [t for t, _ in r6.pruned] == ["Good"] and r6.changed and "### Good" not in read(os.path.join(d4, "seed-sqli.md")))
learn.SOURCES["sqli"].append(("a", "https://owasp.org/a"))

print("\n=== 회귀: 멱등·순서·보존·관문 우회·길이·중복 ===")
learn.SOURCES["sqli"] += [("b", "https://owasp.org/b2"), ("t", "https://owasp.org/t")]
# 잘린 요약 끝 공백 → 재실행마다 날짜가 바뀌던 문제
w = workspace(entry("Trim", "https://owasp.org/t", "x" * 499 + " " + "tail words here " * 10))
P.promote("sqli", w, w, today="2026-10-01")
check("요약 절단 끝 공백 — 다음 주 재실행 변경 없음", P.promote("sqli", w, w, today="2026-10-08").changed is False)
# 일시적 수집 실패로 순서가 뒤집히던 문제
w = workspace(entry("A", "https://owasp.org/a", LONG) + entry("B", "https://owasp.org/b2", LONG))
P.promote("sqli", w, w, today="2026-10-01")
order0 = [e.title for e in P.split_seed(read(os.path.join(w, "seed-sqli.md")))[1]]
with open(os.path.join(w, "learned-sqli.md"), "w", encoding="utf-8") as f:
    f.write(entry("A", "https://owasp.org/a", None) + entry("B", "https://owasp.org/b2", LONG))
rr = P.promote("sqli", w, w, today="2026-10-08")
check("일부 수집 실패해도 기존 순서 유지(변경 없음)",
      rr.changed is False and [e.title for e in P.split_seed(read(os.path.join(w, "seed-sqli.md")))[1]] == order0)
# 승격 섹션 뒤 사람이 덧붙인 절 보존
w = workspace(entry("A", "https://owasp.org/a", LONG))
P.promote("sqli", w, w, today="2026-10-01")
with open(os.path.join(w, "seed-sqli.md"), "a", encoding="utf-8") as f:
    f.write("\n## 참고\n사람이 덧붙인 참고 문단.\n")
with open(os.path.join(w, "learned-sqli.md"), "w", encoding="utf-8") as f:
    f.write(entry("A", "https://owasp.org/a", "Changed " + LONG))
P.promote("sqli", w, w, today="2026-10-08")
t = read(os.path.join(w, "seed-sqli.md"))
check("승격 섹션 뒤 사람이 쓴 절 보존", "사람이 덧붙인 참고 문단." in t and P.is_canonical(t))
# 출처 없는 항목·섹션 안 임의 문장은 정규형 검사로 차단
base_txt = read(os.path.join(SEED_DIR, "seed-sqli.md"))
body0 = P.split_seed(base_txt)[0]
sneak = body0 + "\n" + P.PROMOTED_HEADER + "\n\n### HTB walkthrough\n- 요약: " + LONG + "\n자유 텍스트\n"
check("출처 없는 항목도 관문에 걸림", any(P.check_candidate(e) for e in P.split_seed(sneak)[1]))
check("섹션 안 임의 문장 → 정규형 아님", not P.is_canonical(sneak))
check("promote 출력은 정규형", P.is_canonical(read(os.path.join(w, "seed-sqli.md"))))
_sp = os.path.join(w, "seed-sqli.md")
_before = read(_sp)
with open(_sp, "a", encoding="utf-8") as f:
    f.write("제목 없이 덧붙인 사람의 메모\n")
rr = P.promote("sqli", w, w)
check("섹션 안 형식 밖 문장 → 지우지 않고 중단(오류 보고)",
      "형식 밖" in rr.error and "사람의 메모" in read(_sp) and not rr.changed)
with open(_sp, "w", encoding="utf-8") as f:
    f.write(_before)
# 기존 승격분이 현재 관문을 못 넘으면 정리
w = workspace(entry("A", "https://owasp.org/a", LONG))
P.promote("sqli", w, w, today="2026-10-01")
bad_old = read(os.path.join(w, "seed-sqli.md")).replace(LONG.strip(), "too short")
with open(os.path.join(w, "seed-sqli.md"), "w", encoding="utf-8") as f:
    f.write(bad_old)
with open(os.path.join(w, "learned-sqli.md"), "w", encoding="utf-8") as f:
    f.write(entry("Bx", "https://owasp.org/b2", LONG))
rr = P.promote("sqli", w, w, today="2026-10-08")
check("관문 미달 기존 승격분 정리", [t for t, _ in rr.pruned] == ["A"] and "too short" not in read(os.path.join(w, "seed-sqli.md")))
# 학습 노트 안 같은 URL 중복 → 하나만 승격, 나머지는 사유와 함께 거부
w = workspace(entry("A1", "https://owasp.org/a", LONG) + entry("A2", "https://owasp.org/a", "Other " + LONG))
rr = P.promote("sqli", w, w)
check("중복 URL: 승격 1 · 거부 1(사유 기록)", len(rr.accepted) == 1 and rr.rejected and "중복" in rr.rejected[0][1])
# 길이 상한
w = workspace(entry("A", "https://owasp.org/a", "w " * 300) + entry("B", "https://owasp.org/b2", "v " * 300))
_sp = os.path.join(w, "seed-sqli.md")
_t = read(_sp)
_pad = NOTE_CHARS - 800 - len(P.split_seed(_t)[0])   # 본문+승격 1건은 상한 안, 2건이면 초과
with open(_sp, "w", encoding="utf-8") as f:   # 사람이 쓴 본문(승격 섹션 앞)에 확장
    f.write(_t.replace(P.PROMOTED_HEADER, ("본문 확장 문장. " * 1000)[:_pad] + "\n\n" + P.PROMOTED_HEADER, 1))
rr = P.promote("sqli", w, w)
check(f"시드 길이 {NOTE_CHARS}자 상한 유지(넘치면 오래된 승격분부터 버림)",
      len(read(os.path.join(w, "seed-sqli.md"))) <= NOTE_CHARS and any("상한" in why for _, why in rr.pruned)
      and len(P.split_seed(read(os.path.join(w, "seed-sqli.md")))[1]) == 1)
learn.SOURCES["sqli"] = [x for x in learn.SOURCES["sqli"] if x[1] not in ("https://owasp.org/b2", "https://owasp.org/t")]

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
learn.SOURCES["sqli"] = _REAL_SQLI   # 시험용 가상 출처 원복 — 실제 카탈로그로 검사
bad, over, long_, stale = [], [], [], []
for p in sorted(glob.glob(os.path.join(SEED_DIR, "seed-*.md"))):
    txt = read(p)
    _, es = P.split_seed(txt)
    topic = os.path.basename(p)[len("seed-"):-len(".md")]
    cat = {u for _, u in learn.SOURCES.get(topic, [])}
    stale += [(topic, e.title) for e in es if e.url not in cat]
    if len(es) > P.MAX_ENTRIES:
        over.append(os.path.basename(p))
    bad += [(os.path.basename(p), e.title, P.check_candidate(e)) for e in es if P.check_candidate(e)]
    if len(txt) > NOTE_CHARS:
        long_.append(os.path.basename(p))
check(f"승격 항목 전부 관문 통과 (위반: {bad[:3] or '없음'})", not bad)
check(f"주제당 승격 상한 준수 (위반: {over or '없음'})", not over)
check(f"시드 전문이 RAG 반영 상한({NOTE_CHARS}자) 안 (위반: {long_ or '없음'})", not long_)
check(f"승격 출처가 모두 현재 카탈로그에 있음 (위반: {stale[:3] or '없음'})", not stale)
noncanon = [os.path.basename(p) for p in sorted(glob.glob(os.path.join(SEED_DIR, "seed-*.md")))
            if not P.is_canonical(read(p))]
check(f"승격 섹션이 정규형(임의 문장·출처 없는 항목 없음) (위반: {noncanon or '없음'})", not noncanon)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
