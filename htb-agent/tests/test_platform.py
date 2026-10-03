# 실행: htb-agent 디렉토리에서  python3 tests/test_platform.py
# 멀티플랫폼(HTB/Dreamhack/CTF): 프로파일·스코프·플래그·CTF KB 회귀.
import os
import sys
sys.path.insert(0, "src")
from htb_agent.profiles import get_profile, platform_keys
from htb_agent.scope_guard import ScopeGuard, ScopeViolation, normalize_target
from htb_agent.flag import scan as scan_flags
from htb_agent.knowledge import KnowledgeBase
from htb_agent.command_validator import validate

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== 프로파일 ===")
check("기본 htb", get_profile(None).key == "htb")
check("키 3종", set(platform_keys()) == {"htb", "dreamhack", "ctf"})
check("htb 대역강제", get_profile("htb").enforce_ranges is True)
check("dreamhack 단일타겟", get_profile("dreamhack").enforce_ranges is False)
check("dreamhack DH 접두", "DH" in get_profile("dreamhack").flag_prefixes)
check("ctf single 종류", get_profile("ctf").flag_kind == "single" and get_profile("ctf").is_jeopardy)
try:
    get_profile("nope"); check("미지원 거부", False)
except ValueError:
    check("미지원 거부", True)

print("\n=== normalize_target ===")
check("URL 호스트", normalize_target("http://host.dreamhack.games:8080/path") == "host.dreamhack.games")
check("host:port", normalize_target("10.0.0.5:1337") == "10.0.0.5")
check("순수 IP", normalize_target("10.0.0.5") == "10.0.0.5")

print("\n=== 스코프: HTB 대역강제 ===")
g = ScopeGuard.from_cidr_strings(enforce_ranges=True)
try:
    g.bind_target("1.2.3.4"); check("대역밖 거부", False)
except ScopeViolation:
    check("대역밖 거부", True)

print("\n=== 스코프: CTF 단일타겟 ===")
g2 = ScopeGuard.from_cidr_strings(None, enforce_ranges=False, allow_hostname_target=True)
addr = g2.bind_target("http://chall.ctf.io:9999/")   # 호스트명 타겟
check("호스트명 타겟 바인딩", g2.bound_host == "chall.ctf.io")
r = g2.inspect_command("curl http://chall.ctf.io:9999/robots.txt")
check("바인딩 호스트=TARGET(자동허용)", r.auto_allowed)
r2 = g2.inspect_command("curl http://evil.example.com/")
check("타 호스트=추가확인", not r2.auto_allowed)
# 임의 IP 타겟(대역 미강제) 허용
g3 = ScopeGuard.from_cidr_strings(None, enforce_ranges=False)
g3.bind_target("3.3.3.3")
check("임의 IP 타겟 자동허용", g3.inspect_command("nmap -sV 3.3.3.3").auto_allowed)

print("\n=== 플래그: 단일(CTF) + 접두 ===")
hits = scan_flags("curl http://t/", "응답: DH{w3lc0me_to_dreamhack} 끝",
                  flag_kind="single", prefixes=("DH", "flag"))
check("DH{} 캡처", any(h.value == "DH{w3lc0me_to_dreamhack}" for h in hits))
check("종류=flag", all(h.kind == "flag" for h in hits))
# single 모드에서는 32-hex 해시를 플래그로 오인하지 않음
h2 = scan_flags("cat user.txt", "d41d8cd98f00b204e9800998ecf8427e", flag_kind="single")
check("single: 32-hex 비플래그", h2 == [])

print("\n=== CTF Jeopardy KB ===")
KN = os.path.join(os.path.dirname(__file__), "..", "knowledge")
kb = KnowledgeBase.load(base_dir=KN)
ctf = [r for r in kb.rules if r.source.startswith("user:ctf-jeopardy")]
check("ctf 규칙 3개 로드", len(ctf) == 3)
bad = 0
for r in ctf:
    for tmpl in r.suggest:
        cmd, _ = kb.format_suggestion(tmpl, "10.0.0.5")
        if not validate(cmd).ok:
            bad += 1
check("ctf 명령 검증 통과", bad == 0)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
