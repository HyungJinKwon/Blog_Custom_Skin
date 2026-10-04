# 실행: htb-agent 디렉토리에서  python3 tests/test_approval.py
import sys
sys.path.insert(0, "src")
from htb_agent.approval import explain_command, render_proposal
from htb_agent import ui
from htb_agent.command_validator import validate
from htb_agent.scope_guard import ScopeGuard

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== 옵션-값 페어링 (안전) ===")
ex = explain_command("nmap -sV -oX - 10.129.1.5")
check("바이너리", "바이너리 : nmap" in ex)
check("-oX 값(-) 페어링", "-oX -" in ex)
check("타겟 IP 는 파라미터(오인 방지)", "파라미터 : 10.129.1.5" in ex)
check("부울 -sV 는 단독 옵션", "-sV" in ex.split("옵션")[1].split("파라미터")[0])

ex2 = explain_command("gobuster dir -u http://10.129.1.5 -w list.txt")
check("-u 값 페어링", "-u http://10.129.1.5" in ex2)
check("-w 값 페어링", "-w list.txt" in ex2)

ex3 = explain_command("msfvenom LHOST=10.10.14.5 LPORT=443 -f elf")
check("환경변수형 인자 표기", "LHOST=10.10.14.5" in ex3)
check("-f 는 화이트리스트 밖 → 단독", "-f" in ex3)

ex4 = explain_command("nmap -Pn -p- 10.129.1.5")
check("-p- 결합형은 단독 + IP 파라미터", "-p-" in ex4 and "파라미터 : 10.129.1.5" in ex4)

print("\n=== render_proposal: 범위밖 대상 렌더링(리스트 repr 버그 가드) ===")
ui.set_color_enabled(False)
g = ScopeGuard.from_cidr_strings(["10.129.0.0/16"])
g.bind_target("10.129.1.5")
sres = g.inspect_command("curl http://evil.example.com/ 10.129.1.5")
vrep = validate("curl http://evil.example.com/ 10.129.1.5")
panel = render_proposal("curl http://evil.example.com/ 10.129.1.5", vrep, sres)
check("범위밖 호스트가 평문으로 표기", "evil.example.com" in panel)
check("리스트 repr 미노출(대괄호 없음)", "['" not in panel and "']" not in panel)
check("추가확인 표기", "추가확인" in panel)
# 범위내만일 때는 추가확인 줄 없음
sres2 = g.inspect_command("nmap -sV 10.129.1.5")
vrep2 = validate("nmap -sV 10.129.1.5")
panel2 = render_proposal("nmap -sV 10.129.1.5", vrep2, sres2)
check("범위내 자동허용 표기", "자동허용" in panel2)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
