# 실행: htb-agent 디렉토리에서  python3 tests/test_portscan_fallback.py
import sys

sys.path.insert(0, "src")
from htb_agent.tools.portscan_fallback import DEFAULT_PORTS, PORT_SERVICE, socket_scan

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")


print("=== socket_scan (주입 probe) ===")
# 80, 6379 만 열려 있다고 흉내
open_set = {80: "", 6379: "", 22: "SSH-2.0-OpenSSH_8.2"}
def probe(host, port, timeout):
    return open_set.get(port)   # None 이면 닫힘

res = socket_scan("10.0.0.5", ports=[22, 80, 443, 6379, 8080], probe=probe)
h = res.first_host()
check("any_up True", res.any_up)
check("열린 포트만", sorted(h.open_ports) == [22, 80, 6379])
svc = {p.port: p.service for p in h.ports}
check("80 → http", svc[80] == "http")
check("6379 → redis", svc[6379] == "redis")
check("배너 → product", any(p.port == 22 and "OpenSSH" in p.product for p in h.ports))
check("주소 보존", h.address == "10.0.0.5")

print("\n=== 열린 포트 없음 ===")
res2 = socket_scan("10.0.0.6", ports=[80, 443], probe=lambda h, p, t: None)
check("any_up False", not res2.any_up)
check("seems_down True", res2.first_host().seems_down if hasattr(res2.first_host(), "seems_down") else res2.seems_down)

print("\n=== extra 포트·중복 제거 ===")
seen = []
def probe2(host, port, timeout):
    seen.append(port); return "" if port == 1337 else None
res3 = socket_scan("10.0.0.7", ports=[1337, 1337, 80], probe=probe2)
check("중복 포트 한 번만 스캔", seen.count(1337) == 1)
check("1337 열림", res3.first_host().open_ports == [1337])

print("\n=== 기본 포트 집합 ===")
check("기본 포트에 80·22·445·6379 포함", {80, 22, 445, 6379} <= set(DEFAULT_PORTS))
check("PORT_SERVICE 일관", all(isinstance(v, str) and v for v in PORT_SERVICE.values()))
check("잘못된 포트 무시", socket_scan("10.0.0.8", ports=[0, 70000, 80],
                                 probe=lambda h, p, t: "" if p == 80 else None
                                 ).first_host().open_ports == [80])

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
