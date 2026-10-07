# 실행: htb-agent 디렉토리에서  python3 tests/test_kb_sync.py
# 공유 저장소 최신 시드의 로컬 자동 반영(검증 후 캐시 적용). 네트워크는 주입 fetch 로 모사.
import contextlib
import glob
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, "src")
from htb_agent import kb_sync as K  # noqa: E402
from htb_agent import promote as P  # noqa: E402
from htb_agent.knowledge import KnowledgeBase  # noqa: E402
from htb_agent.main import main  # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

SEED_DIR = "knowledge/notes/learned"
REPO = K.DEFAULT_REPO
RAW = f"https://raw.githubusercontent.com/{REPO}/main/{K.SEED_PATH}/"

def read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()

def workspace():   # git 저장소 밖 임시 지식 디렉토리(로컬 수정 감지 대상 아님)
    k = tempfile.mkdtemp()
    os.makedirs(os.path.join(k, "notes", "learned"))
    shutil.copy(os.path.join(SEED_DIR, "seed-sqli.md"), os.path.join(k, "notes", "learned"))
    return k

class Upstream:
    """GitHub contents API + raw 다운로드 모사. files: {이름: 텍스트}."""
    def __init__(self, files, url_for=None, listing_ok=True, tamper=None):
        self.files, self.calls = files, []
        self.url_for = url_for or (lambda n: RAW + n)
        self.listing_ok, self.tamper = listing_ok, tamper or {}
    def __call__(self, url):
        self.calls.append(url)
        if url.startswith("https://api.github.com/"):
            if not self.listing_ok:
                return None
            return json.dumps([{"name": n, "sha": K.blob_sha(t.encode()), "download_url": self.url_for(n),
                                "type": "file"} for n, t in self.files.items()]).encode()
        for n, t in self.files.items():
            if url == self.url_for(n):
                return self.tamper.get(n, t).encode()
        return None

LOCAL = read(os.path.join(SEED_DIR, "seed-sqli.md"))
NEWER = LOCAL.replace("## 완화", "## 완화\n공유 저장소에서 보강된 완화 문장(동기화 시험용).", 1)

print("=== blob_sha = git 블롭 해시 ===")
check("빈 블롭", K.blob_sha(b"") == "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391")
check("hello\\n", K.blob_sha(b"hello\n") == "ce013625030ba8dba906f756967f9e9ca394464a")

print("\n=== validate_seed: 번들 시드 불변식 + 승격 관문 ===")
check("정상 시드 통과", K.validate_seed("seed-sqli.md", NEWER) is None)
check("파일명 형식", K.validate_seed("../evil.md", NEWER) is not None)
check("너무 짧음", "짧음" in (K.validate_seed("seed-sqli.md", "## 개요\nx") or ""))
check("필수 섹션 누락", "필수 섹션" in (K.validate_seed("seed-sqli.md", NEWER.replace("## 완화", "## 기타")) or ""))
check("권위 출처 없음",
      "출처" in (K.validate_seed("seed-sqli.md", NEWER.replace("https://", "hxxp://")) or ""))
check("제어문자", "제어문자" in (K.validate_seed("seed-sqli.md", NEWER + "\x00") or ""))
check("RAG 상한 초과", K.validate_seed("seed-sqli.md", NEWER + "가" * 7000) is not None)
_body = P.split_seed(NEWER)[0]
_ref = "Reference text describing the concept and its typical defenses. " * 3
junk = P.render_seed(_body, [P.Candidate("Bad", "https://blog.example.com/x", "text " * 40)])
check("승격 항목이 관문 위반", "승격 항목" in (K.validate_seed("seed-sqli.md", junk) or ""))
many = P.render_seed(_body, [P.Candidate(f"E{i}", f"https://owasp.org/e{i}", _ref) for i in range(4)])
check("승격 항목 상한 초과", "상한" in (K.validate_seed("seed-sqli.md", many) or ""))
loose = NEWER.rstrip() + "\n형식 밖 문장\n"
check("승격 섹션 정규 형식 아님 → 거부", "형식" in (K.validate_seed("seed-sqli.md", loose) or ""))
nourl = P.render_seed(_body, [P.Candidate("NoUrl", "", _ref)])
check("출처 없는 승격 항목 → 거부", "출처" in (K.validate_seed("seed-sqli.md", nourl) or ""))
bad = [(os.path.basename(p), K.validate_seed(os.path.basename(p), read(p)))
       for p in sorted(glob.glob(os.path.join(SEED_DIR, "seed-*.md")))]
bad = [b for b in bad if b[1]]
check(f"CI 불변식: 커밋된 시드 전부 동기화 검증 통과 (위반: {bad[:3] or '없음'})", not bad)

print("\n=== sync: 다른 것만 내려받아 검증 후 캐시 적용 ===")
k = workspace()
up = Upstream({"seed-sqli.md": NEWER, "seed-brand-new.md": NEWER})
r = K.sync(k, fetch=up)
check("최신본 반영", r.applied == ["seed-sqli.md"] and not r.rejected and not r.error)
check("로컬에 없는 새 시드는 받지 않음(코드와 함께 와야 함)",
      not any("brand-new" in u for u in up.calls[1:]))
check("추적 시드 파일은 건드리지 않음", read(os.path.join(k, "notes", "learned", "seed-sqli.md")) == LOCAL)
kb = KnowledgeBase.load(k)
check("지식베이스는 캐시본을 로드", any("동기화 시험용" in n for n in kb.notes))
check("시드 중복 로드 없음", sum("[seed-sqli.md]" in n for n in kb.notes) == 1)
n_before = len(up.calls)
r = K.sync(k, fetch=up)
check("같은 버전 재동기화 → 다운로드 없음", r.applied == [] and len(up.calls) == n_before + 1)

print("\n=== 로컬이 최신이면 캐시 정리 / 로컬 갱신(git pull) 시 캐시 무시 ===")
r = K.sync(k, fetch=Upstream({"seed-sqli.md": LOCAL}))
check("공유본 = 로컬 → 캐시본 정리", r.cleared == ["seed-sqli.md"]
      and not os.path.exists(os.path.join(K.cache_dir(k), "seed-sqli.md")))
K.sync(k, fetch=Upstream({"seed-sqli.md": NEWER}))
with open(os.path.join(k, "notes", "learned", "seed-sqli.md"), "a", encoding="utf-8") as f:
    f.write("\n로컬에서 새로 받은 내용\n")
check("동기화 후 추적 시드가 바뀌면 캐시본은 쓰지 않음", K.active_overlays(k) == {})
kb = KnowledgeBase.load(k)
check("→ 로컬 추적 시드를 로드", any("로컬에서 새로 받은 내용" in n for n in kb.notes)
      and not any("동기화 시험용" in n for n in kb.notes))

print("\n=== 거부(fail-safe: 기존 시드 유지) ===")
k = workspace()
r = K.sync(k, fetch=Upstream({"seed-sqli.md": NEWER.replace("## 완화", "## 기타")}))
check("검증 실패 → 거부, 캐시 없음", r.rejected and "필수 섹션" in r.rejected[0][1] and K.active_overlays(k) == {})
r = K.sync(k, fetch=Upstream({"seed-sqli.md": NEWER}, tamper={"seed-sqli.md": NEWER + "변조"}))
check("목록 해시와 내용 불일치 → 거부", r.rejected and "해시" in r.rejected[0][1])
r = K.sync(k, fetch=Upstream({"seed-sqli.md": NEWER}, url_for=lambda n: "https://evil.example.com/" + n))
check("다운로드 주소가 원본 저장소가 아니면 거부", r.rejected and "원본" in r.rejected[0][1])
r = K.sync(k, fetch=Upstream({"seed-sqli.md": NEWER},
                             url_for=lambda n: f"https://raw.githubusercontent.com/other/repo/main/{n}"))
check("다른 저장소의 raw 주소도 거부", r.rejected and "원본" in r.rejected[0][1])
r = K.sync(k, fetch=Upstream({}, listing_ok=False))
check("목록 조회 실패(오프라인) → 오류, 예외 없음", r.error != "" and r.applied == [])
check("저장소 형식 오류", K.sync(k, fetch=up, repo="bad repo").error != "")
check("로컬 시드 디렉토리 없음", K.sync(tempfile.mkdtemp(), fetch=up).error != "")

print("\n=== 로컬에서 직접 수정한(미커밋) 시드는 보존 ===")

k = workspace()
_git = ["git", "-C", k, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"]
if subprocess.run(["git", "init", "-q", k], capture_output=True).returncode == 0:
    subprocess.run(_git + ["add", "-A"], capture_output=True)
    subprocess.run(_git + ["commit", "-qm", "init"], capture_output=True)
    with open(os.path.join(k, "notes", "learned", "seed-sqli.md"), "a", encoding="utf-8") as f:
        f.write("\n편집 중\n")
    r = K.sync(k, fetch=Upstream({"seed-sqli.md": NEWER}))
    check("수정·미커밋 시드 → 동기화 안 함", r.applied == [] and r.rejected
          and "로컬 수정본" in r.rejected[0][1])
    subprocess.run(_git + ["commit", "-qam", "edit"], capture_output=True)
    check("커밋된 깨끗한 시드는 동기화", K.sync(k, fetch=Upstream({"seed-sqli.md": NEWER})).applied == ["seed-sqli.md"])
else:
    check("git 없음 — 건너뜀", True)

print("\n=== 회귀: 로컬 커밋 최신본 · 쓰기 오류 · 줄바꿈 · 사라진 시드 ===")
k = workspace()
if subprocess.run(["git", "init", "-q", k], capture_output=True).returncode == 0:
    _g = ["git", "-C", k, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"]
    subprocess.run(_g + ["add", "-A"], capture_output=True)
    subprocess.run(_g + ["commit", "-qm", "base"], capture_output=True)       # 공유본(LOCAL)과 같은 버전
    with open(os.path.join(k, "notes", "learned", "seed-sqli.md"), "w", encoding="utf-8") as f:
        f.write(NEWER)
    subprocess.run(_g + ["commit", "-qam", "promote"], capture_output=True)   # 로컬이 앞서 커밋
    r = K.sync(k, fetch=Upstream({"seed-sqli.md": LOCAL}))
    check("로컬이 공유본을 거쳐 커밋된 최신본 → 캐시로 덮지 않음",
          r.applied == [] and K.active_overlays(k) == {})
else:
    check("git 없음 — 건너뜀", True)
k = workspace()
with open(os.path.join(k, "shared_seeds"), "w") as f:
    f.write("not a dir")
r = K.sync(k, fetch=Upstream({"seed-sqli.md": NEWER}))
check("캐시 디렉토리 쓰기 불가 → 예외 없이 오류 보고", "캐시" in r.error)
check("auto_sync 도 예외 없이 진행", K.auto_sync(k, fetch=Upstream({"seed-sqli.md": NEWER})).error != "")
k = workspace()
K.sync(k, fetch=Upstream({"seed-sqli.md": NEWER}))
with open(os.path.join(k, "notes", "learned", "seed-sqli.md"), "w", encoding="utf-8", newline="") as f:
    f.write(NEWER.replace("\n", "\r\n"))                                 # git pull(autocrlf) 후
r = K.sync(k, fetch=Upstream({"seed-sqli.md": NEWER}))
check("줄바꿈만 다른 최신 로컬 → 캐시본 정리", r.cleared == ["seed-sqli.md"]
      and not os.path.exists(os.path.join(K.cache_dir(k), "seed-sqli.md")))
k = workspace()
K.sync(k, fetch=Upstream({"seed-sqli.md": NEWER}))
r = K.sync(k, fetch=Upstream({}))
check("공유 저장소에서 사라진 시드 → 캐시본 정리", r.cleared == ["seed-sqli.md"] and K.active_overlays(k) == {})
for v in ("False", "NO", "Off"):
    os.environ["ASSASSIN_NO_KB_SYNC"] = v
    check(f"ASSASSIN_NO_KB_SYNC={v} → 끄지 않음(대소문자 무시)", K.auto_sync(workspace(), fetch=Upstream({})).skipped == "")
del os.environ["ASSASSIN_NO_KB_SYNC"]

print("\n=== auto_sync: 하루 1회 · 끄기 · 오프라인 재시도 억제 ===")
k = workspace()
os.environ["ASSASSIN_NO_KB_SYNC"] = "1"
check("ASSASSIN_NO_KB_SYNC=1 → 건너뜀", K.auto_sync(k, fetch=up).skipped != "")
del os.environ["ASSASSIN_NO_KB_SYNC"]
r = K.auto_sync(k, fetch=Upstream({"seed-sqli.md": NEWER}))
check("첫 실행 → 동기화", r.applied == ["seed-sqli.md"])
check("24시간 안 재실행 → 건너뜀", K.auto_sync(k, fetch=up).skipped != "")
up2 = Upstream({"seed-sqli.md": LOCAL})
import time as _t  # noqa: E402

check("간격 지나면 다시 동기화", K.auto_sync(k, fetch=up2, now=_t.time() + K.INTERVAL + 1).cleared == ["seed-sqli.md"])
k2 = workspace()
off = Upstream({}, listing_ok=False)
K.auto_sync(k2, fetch=off)
check("오프라인 실패 후 다음 실행은 재시도 안 함(타임아웃 대기 방지)",
      K.auto_sync(k2, fetch=off).skipped != "" and len(off.calls) == 1)

print("\n=== knowledge_summary(리포트 '지식 기반' 패널용) ===")
k = workspace()
s0 = K.knowledge_summary(k)
check("기본 집계(시드 1·카탈로그 커버 1)", s0["seed_topics"] == 1 and s0["catalog_covered"] == 1
      and s0["shared_overlays"] == 0 and s0["last_sync"] == "")
K.sync(k, fetch=Upstream({"seed-sqli.md": NEWER}))
s1 = K.knowledge_summary(k)
check("동기화 후 공유 최신본 1·마지막 동기화 시각 기록", s1["shared_overlays"] == 1 and s1["last_sync"].endswith("Z"))
check("승격 발췌 수·최근 승격일", s1["promoted"] >= 1 and len(s1["promoted_latest"]) == 10)
check("없는 디렉토리도 예외 없음", K.knowledge_summary(tempfile.mkdtemp())["seed_topics"] == 0)

print("\n=== CLI ===")
k = workspace()
orig = K._default_fetch
K._default_fetch = lambda timeout=6: Upstream({"seed-sqli.md": NEWER})
out = io.StringIO()
with contextlib.redirect_stdout(out):
    rc = main(["--kb-sync", "--knowledge", k])
check("--kb-sync rc 0 + 결과 출력", rc == 0 and "최신 반영 1개" in out.getvalue())
K._default_fetch = lambda timeout=6: Upstream({}, listing_ok=False)
with contextlib.redirect_stdout(io.StringIO()):
    check("--kb-sync 실패 rc 2", main(["--kb-sync", "--knowledge", workspace()]) == 2)
K._default_fetch = orig
called = []
orig_auto = K.auto_sync
K.auto_sync = lambda *a, **kw: called.append(a) or K.SyncResult()
fr = FakeRunner(lambda c: RunOutput(c, stdout="ok"))
with contextlib.redirect_stdout(io.StringIO()):
    main(["10.129.1.5", "--auto", "--no-save", "--knowledge", workspace()], runner=fr)
check("러너 주입(시험) 실행에서는 자동 동기화 안 함", called == [])
K.auto_sync = orig_auto

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
