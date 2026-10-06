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

print("\n=== 출처 신뢰 등급 ===")
check("OWASP → A", ws.trust_tier("https://owasp.org/x") == "A")
check("MITRE → A", ws.trust_tier("https://attack.mitre.org/x") == "A")
check("NIST → B", ws.trust_tier("https://nvd.nist.gov/x") == "A" or ws.trust_tier("https://www.nist.gov/x") == "B")
check("Wikipedia → B", ws.trust_tier("https://en.wikipedia.org/wiki/SSRF") == "B")
check("일반 블로그 → C", ws.trust_tier("https://randomblog.io/post") == "C")

print("\n=== WebLearner: HTB 라이트업 차단 + 교차검증 ===")
def fake_search(q):
    return [ws.WebResult("OWASP SSRF", "https://owasp.org/ssrf", "ssrf 설명"),
            ws.WebResult("HTB Forest Writeup", "https://0xdf.gitlab.io/htb-forest", "forest writeup"),
            ws.WebResult("Kerberos Explained", "https://blog.example.com/kerb", "kerberos")]
def fake_fetch(url):
    return {"https://owasp.org/ssrf": "<p>SSRF is a server side request forgery attack: a vulnerability that lets attackers exploit the server</p>",
            "https://blog.example.com/kerb": "<p>Kerberos authentication protocol uses tickets TGT TGS on the network</p>",
            }.get(url, "<p>should not fetch writeup</p>")
with tempfile.TemporaryDirectory() as d:
    wl = ws.WebLearner(cache_dir=os.path.join(d, "learned"),
                       fetch_fn=fake_fetch, search_fn=fake_search, enabled=True)
    r = wl.learn("ssrf")
    check("HTB 라이트업 1건 차단", len(r.blocked) == 1 and "0xdf" in r.blocked[0])
    check("차단 URL 은 fetch 안 함", "should not fetch writeup" not in r.excerpt)
    check("Tier A(OWASP) 단독 채택", any(x.url == "https://owasp.org/ssrf" and x.tier == "A" for x in r.refs))
    check("단독 C급 블로그는 미검증 제외", "https://blog.example.com/kerb" in r.unverified)
    note = open(r.note_path, encoding="utf-8").read()
    check("노트에 권위 출처 포함", "owasp.org/ssrf" in note)
    check("노트에 HTB 라이트업/미검증 없음", "0xdf" not in note and "blog.example.com" not in note)
    wl2 = ws.WebLearner(enabled=False, search_fn=fake_search, fetch_fn=fake_fetch)
    check("비활성 시 no-op", wl2.learn("ssrf").refs == [])

print("\n=== 교차검증: 독립 C급 2곳 상호확인되면 채택 ===")
def corro_search(q):
    return [ws.WebResult("Blog A", "https://aaa.io/p", "x"),
            ws.WebResult("Blog B", "https://bbb.io/p", "x")]
# 두 블로그가 핵심 용어를 충분히 공유(독립 등록도메인) → 상호확인 성립
shared = "<p>kerberoasting attack requests service tickets then offline password hash cracking with hashcat against spn accounts on the network</p>"
with tempfile.TemporaryDirectory() as d:
    wl = ws.WebLearner(cache_dir=os.path.join(d, "learned"),
                       fetch_fn=lambda u: shared, search_fn=corro_search, enabled=True)
    r = wl.learn("kerberoasting")
    check("C급 2곳 상호확인 → 둘 다 채택", len(r.refs) == 2 and all(x.corroborators >= 1 for x in r.refs))
    check("미검증 없음(교차확인됨)", r.unverified == [])
# 서로 다른 주제(용어 비공유) C급 2곳 → 상호확인 실패 → 둘 다 미검증
def diff_search(q):
    return [ws.WebResult("A", "https://aaa.io/p", "x"), ws.WebResult("B", "https://bbb.io/p", "x")]
def diff_fetch(u):
    return {"https://aaa.io/p": "<p>alpha beta gamma security attack network exploit</p>",
            "https://bbb.io/p": "<p>monday tuesday wednesday vulnerability password protocol</p>"}.get(u, "")
with tempfile.TemporaryDirectory() as d:
    wl = ws.WebLearner(cache_dir=os.path.join(d, "learned"),
                       fetch_fn=diff_fetch, search_fn=diff_search, enabled=True)
    r = wl.learn("unrelated")
    check("상호확인 안 되는 단독 C급들은 전부 미검증", len(r.refs) == 0 and len(r.unverified) == 2)

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

print("\n=== Wikipedia 폴백(검색엔진 차단 환경) ===")
import json as _json
def wiki_fake(url):
    if "html.duckduckgo.com" in url:
        return "<html>challenge page — no results</html>"      # 봇 차단 모사
    if "action=opensearch" in url:
        return _json.dumps(["ssrf", ["Server-side request forgery"], ["SSRF vuln"],
                            ["https://en.wikipedia.org/wiki/Server-side_request_forgery"]])
    if "prop=extracts" in url:
        return _json.dumps({"query": {"pages": {"1": {"extract": "SSRF is a security vulnerability letting attackers make server requests (attack)."}}}})
    return None
res = ws.search("ssrf", fetch_fn=wiki_fake)
check("검색엔진 무결과 → Wikipedia 폴백", len(res) == 1 and "wikipedia.org" in res[0].url)
body = ws.wiki_fetch(res[0].url, wiki_fake)
check("Wikipedia extracts API 로 깔끔한 본문", body and "SSRF is a security vulnerability" in body)
with tempfile.TemporaryDirectory() as d:
    wl = ws.WebLearner(cache_dir=os.path.join(d, "l"), fetch_fn=wiki_fake, enabled=True)
    r = wl.learn("ssrf")
    check("폴백 결과는 Tier B 로 교차검증 통과", len(r.refs) == 1 and r.refs[0].tier == "B")

print("\n=== 보안 관련성 게이트(동음이의 제외) ===")
check("보안 문서 관련", ws.is_security_relevant("Kerberos is a network authentication protocol"))
check("신화/천체 문서 비관련", not ws.is_security_relevant("Kerberos is a moon of Pluto discovered in 2011"))
def homonym_search(q):
    return [ws.WebResult("Kerberos (moon)", "https://en.wikipedia.org/wiki/Kerberos_(moon)", ""),
            ws.WebResult("Kerberos (protocol)", "https://en.wikipedia.org/wiki/Kerberos_(protocol)", "")]
def homonym_fetch(u):
    if "moon" in u: return "<p>Kerberos is a small moon of Pluto discovered by Hubble.</p>"
    return "<p>Kerberos is a computer network authentication protocol using tickets; attacks include kerberoasting.</p>"
with tempfile.TemporaryDirectory() as d:
    wl = ws.WebLearner(cache_dir=os.path.join(d, "l"), fetch_fn=homonym_fetch, search_fn=homonym_search, enabled=True)
    r = wl.learn("Kerberos")
    check("보안 문서만 채택", [x.url for x in r.refs] == ["https://en.wikipedia.org/wiki/Kerberos_(protocol)"])
    check("동음이의(위성) 문서 제외", any("moon" in u for u in r.unverified))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
