# VM / 외부 타겟 라이브 벤치 (kind: vm)

컨테이너가 아니라 **실제 머신**(HTB·Dreamhack 머신, VirtualBox/VMware/libvirt VM, 물리 호스트)을
타겟으로 삼는 라이브 벤치 템플릿입니다. harness 는 VM 을 만들지 않고, 지정한 주소에 붙거나
`start_cmd` 로 부팅한 뒤 진짜 도구로 풀이합니다.

## 쓰는 법

1. 이 폴더를 복제해 문제별로 만듭니다: `cp -r vm-htb-example vm-forest`
2. `challenge.json` 을 채웁니다:
   - `address` : 타겟 IP/호스트명. 비워 두면 환경변수 `ASSASSIN_VM_<이름대문자>` 로 지정
     (예: 이름이 `vm-forest` → `ASSASSIN_VM_VM_FOREST=10.129.10.5`). 머신마다 IP 가 달라
     파일을 고치지 않고 환경변수로 덮어쓰는 쪽을 권장합니다.
   - `flag` : 채점할 실제 플래그(HTB{...}/flag{...}). **권한이 확인된 본인 인스턴스에서만.**
   - `ranges` : 허용 대역(HTB 대역 등). 비우면 타겟 /32 만 허용.
   - `ports` : 준비성 확인에 쓸 포트(하나면 충분). nmap 있으면 전체 스캔, 없으면 소켓 폴백.
   - `start_cmd`/`stop_cmd` (선택) : VM 을 직접 부팅/종료할 때. 예)
     - libvirt : `start_cmd: "virsh start forest"` / `stop_cmd: "virsh shutdown forest"`
     - VirtualBox : `start_cmd: "VBoxManage startvm forest --type headless"`
     - VMware : `start_cmd: "vmrun start /path/forest.vmx nogui"`
     `start_cmd` 로 '우리가 부팅한' 경우에만 `stop_cmd` 로 정리합니다(이미 떠 있던 머신은 끄지 않음).
3. 실행:
   ```bash
   # VPN 연결(HTB 등) 후, 권한 확인된 본인 타겟에서만
   ASSASSIN_VM_VM_FOREST=10.129.10.5 assassin --live-bench --llm hybrid
   ```

주소가 없으면 그 문제는 `건너뜀(vm)` 으로 표시되고 나머지(loopback/docker)만 실행됩니다.
