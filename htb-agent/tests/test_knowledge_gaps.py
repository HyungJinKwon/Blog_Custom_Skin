# 실행: htb-agent 디렉토리에서  python3 tests/test_knowledge_gaps.py
# 자율 지식 획득(공백 감지·해석·학습, P1 유지) 단위 + 통합.
import os
import sys
import tempfile
sys.path.insert(0, "src")
from htb_agent import knowledge_gaps as kg
from htb_agent import learn

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")


class FakeKB:
    def __init__(self, notes=None):
        self.notes = list(notes or [])


print("=== resolve: 별칭/직접/미해석 ===")
check("직접 주제명", kg.resolve("sqli") == "sqli")
check("제품→주제(mongodb→nosql-injection)", kg.resolve("MongoDB") == "nosql-injection")
check("제품→주제(tomcat→exploit-public-app)", kg.resolve("Apache Tomcat") == "exploit-public-app")
check("서비스→주제(openssh→ssh)", kg.resolve("OpenSSH 8.2") == "ssh")
check("긴 패턴 우선(sql server→sqli)", kg.resolve("Microsoft SQL Server") == "sqli")
check("미해석은 None", kg.resolve("weirdcms9000") is None)
check("빈 문자열 None", kg.resolve("") is None)

print("\n=== detect: 학습가능 vs 미해석 ===")
kb = FakeKB(notes=["[seed-sqli] SQL 주입 ..."])
learnable, unresolved = kg.detect(
    ["mysql", "mongodb", "weirdcms9000", "CVE-2021-1234", "ssh"], kb)
topics = {t for _, t in learnable}
check("mysql/mongo/ssh 해석", {"sqli", "nosql-injection", "ssh"} <= topics)
check("CVE 는 제외(enrich 경로)", all("CVE" not in term for term, _ in learnable))
check("미해석 용어 기록", "weirdcms9000" in unresolved)
check("중복 주제 1회(mysql+mariadb→sqli 한번)",
      len([t for _, t in kg.detect(["mysql", "mariadb"], kb)[0]]) == 1)

print("\n=== detect: already 로 중복 학습 방지 ===")
l2, _ = kg.detect(["mysql"], kb, already={"sqli"})
check("이미 수집한 주제 건너뜀", l2 == [])

print("\n=== detect: KB 가 이미 다루는 미해석 용어는 공백 아님 ===")
kb2 = FakeKB(notes=["custom appliance foobar 설명"])
_, unres2 = kg.detect(["foobar"], kb2)
check("KB 커버 용어는 공백 제외", "foobar" not in unres2)

print("\n=== acquire: 온라인 학습 → KB 즉시 반영 ===")
with tempfile.TemporaryDirectory() as d:
    lr = learn.ReferenceLearner(cache_dir=os.path.join(d, "learned"),
                                fetch_fn=lambda u: "<p>authoritative body text</p>",
                                enabled=True)
    kb3 = FakeKB()
    already = set()
    out = kg.acquire(["mongodb", "weirdcms9000"], kb3, lr, already, budget=6)
    check("학습 기록 존재", any("nosql-injection" in a for a in out.acquired))
    check("미해석 공백 기록", "weirdcms9000" in out.unresolved)
    check("KB 에 노트 즉시 주입", any("자율학습:nosql-injection" in n for n in kb3.notes))
    check("already 갱신(재학습 방지)", "nosql-injection" in already)
    check("노트에 출처 URL 포함", any("portswigger" in n for n in out.notes_added))
    # 두 번째 호출은 already 때문에 재학습 안 함
    out2 = kg.acquire(["mongodb"], kb3, lr, already, budget=6)
    check("중복 호출 재학습 없음", out2.acquired == [])

print("\n=== acquire: budget 상한 ===")
with tempfile.TemporaryDirectory() as d:
    lr = learn.ReferenceLearner(cache_dir=os.path.join(d, "learned"),
                                fetch_fn=lambda u: "<p>x</p>", enabled=True)
    kb4 = FakeKB()
    out = kg.acquire(["mysql", "mongodb", "ssh", "ftp", "smtp"], kb4, lr, set(), budget=2)
    check("budget=2 → 최대 2개 학습", len(out.acquired) <= 2)

print("\n=== acquire: 오프라인 → 포인터만(KB 주입 안 함) ===")
with tempfile.TemporaryDirectory() as d:
    lr = learn.ReferenceLearner(cache_dir=os.path.join(d, "learned"),
                                fetch_fn=lambda u: "SHOULD-NOT-FETCH", enabled=False)
    kb5 = FakeKB()
    out = kg.acquire(["mongodb"], kb5, lr, set(), budget=6)
    check("오프라인: 발췌 없어 KB 미주입", out.notes_added == [])

print("\n=== acquire: learner 없음 → 미해석 공백만 기록 ===")
kb6 = FakeKB()
out = kg.acquire(["mongodb", "weirdcms9000"], kb6, None, set(), budget=6)
check("learner None → acquired 없음", out.acquired == [])
check("learner None → 미해석은 기록", "weirdcms9000" in out.unresolved)

print("\n=== 안전: 모든 별칭 타깃이 실제 주제(번들 시드 보유) ===")
bad = [v for v in kg.ALIASES.values() if v not in set(learn.SOURCES)]
check(f"별칭 타깃 전부 유효 주제 (위반: {bad or '없음'})", not bad)
# 별칭이 가리키는 주제는 번들 시드가 반드시 존재해야 한다(오프라인 완비)
seed_dir = "knowledge/notes/learned"
seeds = {f[len("seed-"):-3] for f in os.listdir(seed_dir)
         if f.startswith("seed-") and f.endswith(".md")}
bad_seed = [v for v in set(kg.ALIASES.values()) if v not in seeds]
check(f"별칭 타깃 주제 전부 번들 시드 보유 (위반: {bad_seed or '없음'})", not bad_seed)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
