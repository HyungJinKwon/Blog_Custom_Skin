# 실행: htb-agent 디렉토리에서  python3 tests/test_world.py
# 월드 모델(구조화 상태) 단위 검증.
import sys
sys.path.insert(0, "src")
from htb_agent.world import WorldModel, ACCESS_ORDER

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== 서비스 추가·보강·중복 ===")
w = WorldModel(target="10.10.10.5")
w.add_service(80, "tcp", "http", "Apache", "")
w.add_service(80, "tcp", "http", "", "2.4.49")   # 같은 포트 → 보강
check("중복 포트 병합", len(w.services) == 1)
check("정보 보강(version)", w.services[0].version == "2.4.49")
w.add_service(22, "tcp", "ssh")
check("새 포트 추가", len(w.services) == 2)
check("label 렌더", "80/tcp http (Apache 2.4.49)" == w.services[0].label())

print("\n=== 권한 레벨 단조 상승 ===")
check("초기 none", w.access_level == "none")
w.add_cred("admin:pass")
check("크리덴셜 → credentialed", w.access_level == "credentialed")
w.add_flag("user", "abc")
check("user 플래그 → user", w.access_level == "user")
w.add_flag("root", "def")
check("root 플래그 → root", w.access_level == "root")
w.raise_access("none")   # 되돌아가지 않음
check("레벨 하락 안 함", w.access_level == "root")
check("has_access(user) True", w.has_access("user"))
check("has_access 순서 정의", ACCESS_ORDER["root"] > ACCESS_ORDER["user"] > ACCESS_ORDER["credentialed"])

print("\n=== 크리덴셜·수집물·취약점 중복 제거 ===")
w2 = WorldModel(target="t")
w2.add_cred("a:b"); w2.add_cred("a:b"); w2.add_cred("")
check("크리덴셜 중복/빈값 제거", w2.creds == ["a:b"])
w2.add_loot("해시: $6$x"); w2.add_loot("해시: $6$x")
check("수집물 중복 제거", w2.loot == ["해시: $6$x"])
w2.add_vuln("CVE-2021-4034"); w2.add_vuln("CVE-2021-4034")
check("취약점 중복 제거", w2.proven_vulns == ["CVE-2021-4034"])

print("\n=== context_lines / to_dict ===")
cl = w.context_lines()
check("context 권한레벨 포함", any("권한레벨=root" in x for x in cl))
check("context 서비스 포함", any("서비스:" in x for x in cl))
d = w.to_dict()
check("to_dict 핵심 키", {"target","os_class","access_level","services","creds","flags"} <= set(d))
check("to_dict 서비스 직렬화", d["services"][0]["port"] == 80)
check("to_dict flags", d["flags"].get("root") == "def")

print("\n=== 확신도 표기(0~1 값 → 백분율) ===")
w3 = WorldModel(target="t")
w3.os_class, w3.os_confidence = "windows_ad", 0.92
check("LLM 컨텍스트: 0.92 → 92%", "확신 92%" in w3.context_lines()[0])
from htb_agent import ui  # noqa: E402
ui.set_color_enabled(False)
check("상태 요약: 0.92 → 92%", "(92%)" in w3.summary())
check("'1%' 오표기 없음", "1%)" not in w3.context_lines()[0])

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
