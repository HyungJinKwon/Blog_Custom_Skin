# 실행: htb-agent 디렉토리에서  python3 tests/test_enrich.py
# CVE/CWE 자동 수집(주입식 fetcher로 오프라인 안전 검증).
import json
import os
import sys
import tempfile
sys.path.insert(0, "src")
from htb_agent.enrich import Enricher

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

# 가짜 NVD + GitHub 응답
NVD = {"vulnerabilities": [{"cve": {
    "descriptions": [{"lang": "en", "value": "Example RCE in Foo <= 1.2."}],
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}, "baseSeverity": "CRITICAL"}]},
    "weaknesses": [{"description": [{"value": "CWE-78"}]}],
    "references": [{"url": "https://example.com/advisory"}],
}}]}
GH = {"items": [{"html_url": "https://github.com/poc/CVE-2024-9264"}]}

def fake_fetch(url):
    if "services.nvd.nist.gov" in url:
        return json.dumps(NVD)
    if "api.github.com" in url:
        return json.dumps(GH)
    return None

print("=== enrich_cve (fake fetcher) ===")
d = tempfile.mkdtemp()
e = Enricher(cache_dir=d, fetch_fn=fake_fetch, enabled=True)
info = e.enrich_cve("CVE-2024-9264")
check("CVE 파싱", info is not None and info.id == "CVE-2024-9264")
check("설명", "RCE" in info.description)
check("CVSS/심각도", info.cvss == "9.8" and info.severity == "CRITICAL")
check("CWE 추출", "CWE-78" in info.cwe)
check("참조 링크", any("advisory" in r for r in info.references))
check("GitHub PoC", any("github.com" in p for p in info.poc_repos))

print("\n=== 캐시 ===")
check("캐시 파일 생성", os.path.exists(os.path.join(d, "CVE-2024-9264.json")))
# fetcher 를 모두 None 으로 바꿔도 캐시에서 로드
e2 = Enricher(cache_dir=d, fetch_fn=lambda u: None, enabled=True)
check("캐시 재사용(네트워크 없이)", e2.enrich_cve("CVE-2024-9264") is not None)

print("\n=== 오프라인/비활성 안전 ===")
d2 = tempfile.mkdtemp()
off = Enricher(cache_dir=d2, fetch_fn=lambda u: None, enabled=False)
check("비활성 시 None", off.enrich_cve("CVE-2024-9264") is None)
check("비활성 시 예외 없음(일괄)", off.enrich(["CVE-2024-9264"]) == [])
# 잘못된 JSON 도 안전
bad = Enricher(cache_dir=tempfile.mkdtemp(), fetch_fn=lambda u: "<<not json>>")
check("깨진 응답 안전", bad.enrich_cve("CVE-2024-9264") is None)
check("잘못된 CVE 형식 무시", e.enrich_cve("NOT-A-CVE") is None)

print("\n=== CWE 이름 ===")
check("CWE 번들 이름", Enricher.cwe_name("CWE-89") == "SQL Injection")
check("CWE URL", Enricher.cwe_name("CWE-611") == "XML External Entity (XXE)")
check("미등록 CWE 빈값", Enricher.cwe_name("CWE-99999") == "")

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
