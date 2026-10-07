# 실행: htb-agent 디렉토리에서  python3 tests/test_environment_util.py
# 환경 프리플라이트(environment)·공용 유틸(util) — 직접 테스트가 없던 모듈 보강.
import subprocess
import sys
sys.path.insert(0, "src")
from htb_agent import environment as env
from htb_agent.util import binary_of

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")


print("=== util.binary_of ===")
check("기본", binary_of("nmap -sV 10.0.0.1") == "nmap")
check("환경변수 할당 건너뜀", binary_of("FOO=1 BAR=2 curl -i http://t") == "curl")
check("경로 유지(기본)", binary_of("/usr/bin/nmap -sV t") == "/usr/bin/nmap")
check("경로 제거(strip_path)", binary_of("/usr/bin/nmap -sV t", strip_path=True) == "nmap")
check("따옴표 불균형도 안전", binary_of('echo "unterminated') == "echo")
check("빈 문자열", binary_of("") == "")


class _Out:
    def __init__(self, stdout): self.stdout = stdout


def _with_ip_output(text):
    """subprocess.run 을 가짜 'ip addr' 출력으로 교체한 뒤 detect_vpn_ips 실행."""
    orig = subprocess.run
    subprocess.run = lambda *a, **k: _Out(text)
    try:
        return env.detect_vpn_ips()
    finally:
        subprocess.run = orig


print("\n=== environment.detect_vpn_ips ===")
IP_OUT = ("1: lo    inet 127.0.0.1/8 scope host lo\n"
          "2: eth0    inet 192.168.0.10/24 brd 192.168.0.255 scope global eth0\n"
          "5: tun0    inet 10.10.14.5/23 scope global tun0\n")
check("tun0 IP 만 추출", _with_ip_output(IP_OUT) == ["10.10.14.5"])
check("VPN 없으면 빈 목록", _with_ip_output("2: eth0    inet 192.168.0.10/24\n") == [])
check("'tunnel' 같은 유사 이름 오탐 없음",
      _with_ip_output("3: tunnel9x    inet 10.9.9.9/24\n") == [])


def _raise(*a, **k):
    raise FileNotFoundError("ip")


orig = subprocess.run
subprocess.run = _raise
try:
    check("ip 명령 없음 → 빈 목록(예외 흡수)", env.detect_vpn_ips() == [])
finally:
    subprocess.run = orig

print("\n=== environment.preflight ===")
rep = env.preflight()
check("PreflightReport 반환", isinstance(rep, env.PreflightReport))
check("ok 는 경고 유무와 일치", rep.ok == (len(rep.warnings) == 0))
check("Python 정보 포함", any("Python" in i for i in rep.info + rep.warnings))
check("render 문자열", isinstance(rep.render(), str) and "VPN" in rep.render())
rep2 = env.preflight(["__nonexistent_tool__"])
check("미등록 필수 도구 → 경고·ok False", rep2.ok is False and rep2.warnings)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
