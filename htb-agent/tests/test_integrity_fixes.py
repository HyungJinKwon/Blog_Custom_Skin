# 실행: htb-agent 디렉토리에서  python3 tests/test_integrity_fixes.py
# 전체 정합성 감사 수정(A: config 버그 · B: 반배선 기능 배선 · C: 중복 제거) 회귀 테스트
import json
import os
import sys
import tempfile

sys.path.insert(0, "src")
from htb_agent.config import Config, ConfigError

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== A. config↔CLI 드리프트 버그 수정 ===")
# vm 샌드박스는 CLI·구현이 지원 → 설정 파일로도 허용돼야 한다
c = Config.from_dict({"sandbox": "vm"})
check("설정 파일 sandbox: vm 허용", c.sandbox == "vm")
for sk in ("none", "shell", "docker", "vm"):
    Config.from_dict({"sandbox": sk})   # 예외 없어야 함
try:
    Config.from_dict({"sandbox": "qemu"})
    _rejected = False
except ConfigError:
    _rejected = True
check("알 수 없는 sandbox 는 여전히 거부", _rejected)
# time_budget·max_cost 는 소수 허용(CLI type=float·dataclass float)
c = Config.from_dict({"time_budget": 30.5, "max_cost": 1.5})
check("설정 파일 time_budget 소수 허용", c.time_budget == 30.5)
check("설정 파일 max_cost 소수 허용", c.max_cost == 1.5)
check("정수도 허용", Config.from_dict({"time_budget": 30}).time_budget == 30)

print("\n=== B. 반배선 기능 배선 ===")
# B1: CredentialVault.load_file — JSON 파일에서 자격증명 로드
from htb_agent.creds import CredentialVault
with tempfile.TemporaryDirectory() as d:
    p = os.path.join(d, "creds.json")
    json.dump([{"username": "admin", "password": "pw", "domain": "corp"}], open(p, "w"))
    v = CredentialVault.load_file(p)
    check("load_file 로 자격증명 로드", len(v.creds) == 1 and v.creds[0].username == "admin")
    check("없는 파일은 빈 볼트(예외 없음)", CredentialVault.load_file(os.path.join(d, "nope.json")).creds == [])

# B2: StateStore.list_targets — 저장된 세션 목록
from htb_agent.state import StateStore
with tempfile.TemporaryDirectory() as d:
    open(os.path.join(d, "10.129.1.5.json"), "w").write("{}")
    open(os.path.join(d, "10.129.1.9.json"), "w").write("{}")
    open(os.path.join(d, "ignore.txt"), "w").write("x")
    ts = StateStore(d).list_targets()
    check("list_targets 가 세션 .json 만 집계", ts == ["10.129.1.5", "10.129.1.9"])
    check("빈/없는 디렉터리는 []", StateStore(os.path.join(d, "none")).list_targets() == [])

# B3: cwe_url 이 HTML 리포트 CWE 링크로 연결됨
from htb_agent.report_export import _cwe_link
link = _cwe_link("CWE-79")
check("cwe_link 가 MITRE 정의 URL 로 연결", "cwe.mitre.org/data/definitions/79.html" in link and "<a href" in link)

print("\n=== C. 중복 fetcher 통합(util.http_get_text) ===")
from htb_agent.util import http_get_text
old = os.environ.get("ASSASSIN_NO_NET")
os.environ["ASSASSIN_NO_NET"] = "1"
try:
    check("network_blocked 면 None(실요청 안 함)", http_get_text("http://example.com") is None)
finally:
    if old is None: del os.environ["ASSASSIN_NO_NET"]
    else: os.environ["ASSASSIN_NO_NET"] = old
# enrich·learn 기본 fetcher 가 공용 헬퍼로 위임되는지(차단 시 None)
os.environ["ASSASSIN_NO_NET"] = "1"
try:
    from htb_agent.enrich import _default_fetcher as enrich_fetch
    from htb_agent.learn import _default_fetcher as learn_fetch
    check("enrich 기본 fetcher 공용 위임", enrich_fetch()("http://example.com") is None)
    check("learn 기본 fetcher 공용 위임", learn_fetch()("http://example.com") is None)
finally:
    if old is None: os.environ.pop("ASSASSIN_NO_NET", None)
    else: os.environ["ASSASSIN_NO_NET"] = old

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
