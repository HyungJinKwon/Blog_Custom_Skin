# 실행: htb-agent 디렉토리에서  python3 tests/test_web_search.py
# 인터넷 검색 학습 + HTB 라이트업 가드(공식·제3자 전부 차단, 일반 학습 허용).
import os
import sys
import tempfile
sys.path.insert(0, "src")
from htb_agent import web_search as ws
from htb_agent import knowledge_gaps as kg

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")


class FakeKB:
    def __init__(self, notes=None): self.notes = list(notes or [])


print("=== HTB 라이트업 가드 ===")
# 차단되어야 하는 것들(공식·제3자 HTB 라이트업)
check("0xdf HTB 라이트업 차단",
      ws.is_htb_writeup("https://0xdf.gitlab.io/2021/01/01/htb-forest.html", "HTB Forest", ""))
check("ippsec 차단", ws.is_htb_writeup("https://ippsec.rocks/forest", "Forest", ""))
check("hackthebox.com 공식 차단",
      ws.is_htb_writeup("https://www.hackthebox.com/machines/forest/writeup", "Forest Writeup", ""))
check("htbmachines 차단", ws.is_htb_writeup("https://htbmachines.com/forest", "", ""))
check("일반 블로그 HTB writeup 차단(맥락+신호)",
      ws.is_htb_writeup("https://someblog.io/posts/x", "Hack The Box Forest Walkthrough", ""))
check("스니펫 신호로 차단",
      ws.is_htb_writeup("https://medium.com/@x/p", "My post", "A full HTB machine writeup for Forest"))
# 허용되어야 하는 것들(일반 학습 — HTB 라이트업 아님)
check("OWASP 문서 허용", not ws.is_htb_writeup("https://owasp.org/www-community/attacks/SQL_Injection", "SQLi", ""))
check("PortSwigger 기법글 허용", not ws.is_htb_writeup("https://portswigger.net/web-security/ssrf", "SSRF", ""))
check("일반 Kerberos 블로그 허용",
      not ws.is_htb_writeup("https://blog.example.com/kerberos-explained", "Kerberos Explained", "deep dive"))
check("비-HTB 워크스루 글도 허용(HTB 아님)",
      not ws.is_htb_writeup("https://blog.example.com/vulnhub-xyz", "VulnHub walkthrough", "walkthrough"))

print("\n=== DuckDuckGo 결과 파싱(주입 fetch) ===")
CANNED = ('<div><a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fowasp.org%2Fssrf">'
          'OWASP SSRF</a><a class="result__snippet">Server side request forgery 설명</a></div>'
          '<div><a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2F0xdf.gitlab.io%2Fhtb-forest">'
          'HTB Forest Writeup</a><a class="result__snippet">forest writeup</a></div>')
results = ws.search("ssrf", fetch_fn=lambda u: CANNED)
check("결과 2건 파싱", len(results) == 2)
check("리다이렉트 디코딩(실 URL)", results[0].url == "https://owasp.org/ssrf")
check("빈 검색 결과 안전", ws.search("x", fetch_fn=lambda u: None) == [])

print("\n=== WebLearner: HTB 라이트업 차단하고 일반 학습만 수집 ===")
def fake_search(q):
    return [ws.WebResult("OWASP SSRF", "https://owasp.org/ssrf", "ssrf 설명"),
            ws.WebResult("HTB Forest Writeup", "https://0xdf.gitlab.io/htb-forest", "forest writeup"),
            ws.WebResult("Kerberos Explained", "https://blog.example.com/kerb", "kerberos")]
def fake_fetch(url):
    return {"https://owasp.org/ssrf": "<p>SSRF is server side request forgery technique</p>",
            "https://blog.example.com/kerb": "<p>Kerberos uses tickets TGT TGS</p>",
            }.get(url, "<p>should not fetch writeup</p>")
with tempfile.TemporaryDirectory() as d:
    wl = ws.WebLearner(cache_dir=os.path.join(d, "learned"),
                       fetch_fn=fake_fetch, search_fn=fake_search, enabled=True)
    r = wl.learn("ssrf")
    check("일반 결과 2건 채택", len(r.refs) == 2)
    check("HTB 라이트업 1건 차단", len(r.blocked) == 1 and "0xdf" in r.blocked[0])
    check("차단 URL 은 fetch 안 함(본문에 writeup 없음)", "should not fetch writeup" not in r.excerpt)
    check("노트 생성", os.path.isfile(r.note_path))
    note = open(r.note_path, encoding="utf-8").read()
    check("노트에 일반 출처 포함", "owasp.org/ssrf" in note)
    check("노트에 HTB 라이트업 출처 없음", "0xdf" not in note)
    # 오프라인/비활성
    wl2 = ws.WebLearner(enabled=False, search_fn=fake_search, fetch_fn=fake_fetch)
    check("비활성 시 no-op", wl2.learn("ssrf").refs == [])

print("\n=== knowledge_gaps: 미해석 공백 → 웹학습 연결 ===")
with tempfile.TemporaryDirectory() as d:
    wl = ws.WebLearner(cache_dir=os.path.join(d, "learned"),
                       fetch_fn=fake_fetch, search_fn=fake_search, enabled=True)
    kb = FakeKB()
    # 'weirdproto9000' 은 카탈로그 밖(미해석) → 웹학습 시도
    out = kg.acquire(["weirdproto9000"], kb, learner=None, already=set(),
                     budget=6, web_learner=wl)
    check("미해석 공백이 웹학습으로 채워짐", any("(웹)" in a for a in out.acquired))
    check("웹학습 노트 KB 주입", any("웹학습:" in n for n in kb.notes))
    # web_learner 없으면 미해석으로 남음
    out2 = kg.acquire(["weirdproto9000"], FakeKB(), learner=None, already=set(), budget=6)
    check("web_learner 없으면 미해석 기록", "weirdproto9000" in out2.unresolved)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
