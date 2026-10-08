# 실제 Kali 라이브 검증 가이드 (수용 테스트 런북)

이 문서는 **권한이 확인된 본인 환경(Kali + HTB VPN)** 에서 ASSASSIN 을 처음부터 끝까지
검증하는 단계별 체크리스트다. 각 단계는 **명령 → 기대 결과 → 판정(✅/❌)** 으로 되어 있고,
막히면 바로 옆의 '막히면' 포인터를 따른다. 발표·심사 전 리허설, 또는 설치 직후 수용 테스트용.

> ⚠️ **범위**: HTB·Dreamhack·CTF·서면 인가된 진단 대상에서만. 다른 자산에 쓰지 말 것.
> 네트워크 없이 흐름만 보려면 `python3 scripts/demo.py` (이 문서의 P0 가 그것).
> 명령은 **`assassin`** (옛 `htb-agent` 도 동일 별칭).

## 사전 준비

| 필요 | 용도 | 없으면 건너뛸 단계 |
|---|---|---|
| Kali/Ubuntu + root(sudo) | 도구 설치·표준 포트 바인딩 | — |
| HTB(또는 랩) VPN `.ovpn` | 실제 머신 접속 | P3·P7 (오프라인 P0·P1·P6-loopback 은 가능) |
| Docker 데몬 | 완전자율 샌드박스·docker 라이브 문제 | P4·P6-docker |
| 전용 공격 VM + SSH 키 | VM 실행 샌드박스 | P5 |
| Claude API 키 또는 Ollama | LLM 두뇌(hybrid) | P1-LLM·LLM 켠 라이브 벤치 |

검증 소요: 오프라인(P0~P2,P6) 약 10분 · 실제 머신(P3~P5,P7) 머신당 15~45분.

---

## P0. 오프라인 전체 흐름 (네트워크·실도구 불필요)

가장 먼저 코드가 멀쩡한지 네트워크 없이 확인한다.

```bash
cd htb-agent
pip install -e .                       # 'assassin' 명령 생성
python3 tests/run_all.py               # 전체 테스트
python3 scripts/demo.py --live         # 7단계 라이브 데모(안전 경계 중심)
assassin --bench --offline             # 오프라인 모의 문제 성능 측정
```

- **기대**: `run_all` 마지막 줄 `… passed, 0 failed · 실패 스위트 0` ·
  데모 7단계(타겟바인딩→정찰→열거→3관문→지식→산출→성능)가 순서대로 출력되고 '위험 명령 실행 0' ·
  `--bench` 가 표와 `풀린 문제 N/12` 출력.
- 판정: ☐ 테스트 올그린  ☐ 데모 완주  ☐ 벤치 표 출력
- 막히면: 설치 실패면 `pip install -e .` 재실행 · Python 3.10+ 확인(`python3 --version`).

---

## P1. 환경 점검 + LLM 연결

```bash
assassin --doctor                      # 도구·VPN·LLM·실행 샌드박스 한눈에(스캔 안 함)
assassin --setup-llm                   # (선택) Claude 키/Ollama 연결 마법사 — 한 번만
assassin --llm-test                    # (선택) LLM 실제 1회 호출 확인(틀린 키/없는 모델 탐지)
```

- **기대**: `--doctor` 가 시스템·핵심도구·LLM·**3.5 실행 샌드박스**·다음 단계 5개 패널을 출력.
  치명적 문제(예: Python < 3.10)만 빨간색, 나머지는 안내. `--llm-test` 는 `LLM 호출 성공` 또는
  틀린 키/모델을 **가린 값**과 함께 한 줄로 알림.
- 판정: ☐ doctor 5개 패널  ☐ (LLM 쓰면) `--llm-test` 성공
- 막히면: LLM 키 오류 메시지의 안내대로. 키 없이도 규칙기반으로 전 기능 동작(`--llm none`).

---

## P2. 보안 도구 + VPN

```bash
sudo ./scripts/install_tools.sh        # 전체(또는: recon web smb ad creds cloud pwn …)
sudo openvpn your-lab.ovpn &            # HTB VPN — tun0 생성 → 공격자 IP 자동탐지
assassin --doctor                      # 재점검: 도구 초록, VPN(tun/tap) IP 표시
```

- **기대**: `--doctor` 핵심 도구가 대부분 초록 · `VPN(tun/tap) IP: 10.10.14.x` 표시.
  `nmap` 이 있어야 정찰이 full-스캔으로 동작(없으면 소켓 폴백으로라도 진행).
- 판정: ☐ 핵심 도구 초록  ☐ tun0 IP 탐지
- 막히면: 특정 도구 실패는 무시 가능(install_tools 는 하나 실패해도 계속). VPN 미탐지면
  `--attacker-ip 10.10.14.x` 로 수동 지정 가능.

---

## P3. 실제 HTB 머신 — 승인제(기본) 한 바퀴

가장 쉬운 Starting Point 급 머신 1대로 '정찰→식별→열거→리포트'를 끝까지 돈다.

```bash
assassin 10.129.X.Y --json --html      # 스마트 승인(범위 밖만 사람 확인)
# 또는 완전자동(무프롬프트, 범위 밖은 조용히 건너뜀):
assassin 10.129.X.Y --auto --json --html
```

- **기대**:
  - 세션 박스(플랫폼/타겟/범위/공격자IP/승인모드) → RECON 열린 포트 → OS 식별 →
    단계별 열거 → 끝에 **'한눈에 보기'** + PROVENANCE(플래그 잡으면).
  - 플래그를 잡았다면 출처가 `공략 유래(검증)` 인지 확인(= `exploit-derived`).
  - `state/report_10.129.X.Y.{json,html}` 생성. HTML 상단 '한눈에 보기' + 가설 보드.
  - 종료코드: `echo $?` → 0(완료)·1(미완)·2(인자/범위 오류)·130(Ctrl+C).
- 판정: ☐ 포트 발견  ☐ 열거 자동 실행  ☐ 리포트 JSON/HTML  ☐ (플래그 시) 출처=공략 유래
- 막히면: '열린 포트 미확보'면 VPN/대상 IP 재확인 · `--manual` 로 한 명령씩 보며 디버그 ·
  중단했다면 같은 명령에 `--resume`.

### P3b. 두뇌(LLM) 켜고 비교

```bash
assassin 10.129.X.Y --llm hybrid --json --html
```

- **기대**: 실행 끝에 `라우팅: 로컬 N · 강력 N · 폴백 …` 비용 요약. KB만으로 막히던 체인
  (예: robots→숨은 경로)이 더 풀림. Claude 백엔드면 **네이티브 tool use** 로 명령이 구조화되어 제안.
- 판정: ☐ 라우팅 요약 출력  ☐ LLM 제안 명령 실행됨

---

## P4. 완전자율 + 실제 익스플로잇 (Docker 샌드박스)

egress 방화벽으로 묶인 Kali 컨테이너 안에서 스크립트·동적 실행까지 자동으로 돈다.

```bash
./scripts/build_sandbox.sh             # 최초 1회(Kali 이미지 빌드, 수 분)
assassin 10.129.X.Y --autonomous --sandbox docker --llm hybrid --json --html
```

- **기대**:
  - 시작 시 `샌드박스: docker … · egress 허용 10.129.X.Y/32` 출력(타겟 대역만 허용).
  - LLM 이 쓴 익스플로잇/솔버 스크립트가 **작성·실행**되고 감사로그에 `file_written` 기록.
  - 파이프·리다이렉트가 동작(비-샌드박스 none 모드에서는 셸 연산자 거부됨).
  - **안전 경계**: 범위 밖·파괴명령은 여전히 거부. 컨테이너는 끝나면 자동 정리.
- 판정: ☐ egress 허용 로그  ☐ 스크립트 작성·실행  ☐ 범위 밖 차단 유지
- 막히면: `샌드박스 시작 실패` 면 `docker info` 로 데몬 확인 · `docker` 그룹 권한 ·
  이미지 재빌드. 샌드박스 없이 돌리려면 `--sandbox none`(동적 실행은 수동 제안으로).

---

## P5. VM 실행 샌드박스 (Docker 대신 가상머신에서 실행)

전용 공격 VM(Kali 등)에서 SSH 로 명령을 실행한다.

```bash
# VM 에 키 기반 SSH 가 비밀번호 없이 되는지 먼저 확인
ssh kali@192.168.56.10 true && echo "ssh ok"

assassin 10.129.X.Y --sandbox vm --vm-ssh kali@192.168.56.10 \
         --vm-ssh-key ~/.ssh/id_ed25519 --llm hybrid --json --html
# 완전자율 동적 실행까지 자동으로 하려면(그 VM 네트워크를 타겟으로 제한):
assassin 10.129.X.Y --autonomous --sandbox vm --vm-ssh kali@192.168.56.10 \
         --vm-confine --vm-sudo --llm hybrid
```

- **기대**:
  - `실행기: vm kali@… · egress …`(--vm-confine 시 egress 강제) 또는 `네트워크 강제 없음`.
  - 명령이 VM 에서 실행되고, LLM 스크립트는 scp 로 VM 에 올라가 실행됨.
  - `--vm-confine` 없으면 동적 실행은 **수동 제안**으로 남음(안전).
- 판정: ☐ VM 접속 성공  ☐ 명령 VM 에서 실행  ☐ (confine 시) egress 강제 로그
- 막히면: `VM SSH 접속 실패` 면 `ssh ...` 가 비번 없이 되는지 · VM 이 타겟에 닿는지(VPN) ·
  `--vm-confine` 은 전용 VM 에서만(그 VM 네트워크를 타겟으로 제한함).

---

## P6. 라이브 성능 벤치마크 (발표용 수치)

실제 서비스를 띄우고 진짜 도구로 풀어 **검증된 풀이율**을 측정한다.

```bash
assassin --live-bench --attempts 1                 # KB만(규칙기반) 기준선
assassin --live-bench --attempts 3 --llm hybrid    # LLM 켜고 pass@3
```

- **기대**:
  - loopback 문제(web-robots/header/source-comment·net-banner·cookie·lfi)는 어디서나 실행.
    docker 문제(ftp/redis/smb/mysql/snmp)는 데몬 있으면 실행, 없으면 '건너뜀' 명시.
  - 표 + `풀린 문제 N/M (pass@k)` + **`검증된 풀이율 100% (대상 상호작용 유래)`**.
  - LLM 을 켜면 체인 문제(robots→숨은 경로·쿠키 우회·LFI)가 추가로 풀림.
  - 실제 머신(HTB)을 벤치 타겟으로 쓰려면 `vm` 문제: `bench/live/vm-htb-example/` 복제 후
    `ASSASSIN_VM_<이름>=<IP> assassin --live-bench`.
- 판정: ☐ loopback 풀이  ☐ (docker 데몬 시) 실서비스 풀이  ☐ 검증된 풀이율 표시
- 막히면: docker 문제가 전부 '건너뜀'이면 데몬 미기동 — P4 와 동일.

---

## P7. 산출물 — 리포트·라이트업·재생

```bash
assassin 10.129.X.Y --llm hybrid --writeup --writeup-format tistory --json --html
assassin --replay state/audit_10.129.X.Y.jsonl          # 단계별 타임라인 HTML
```

- **기대**: `writeup_*.md`(HTB v5 또는 Tistory 13섹션) · `report_*.{json,html}` · 재생 HTML.
  JSON 에 `plan`(가설 보드)·`gate_stats`(3관문 지표)·`flag_provenance` 포함.
- 판정: ☐ 라이트업  ☐ 대시보드 HTML  ☐ 재생 HTML

---

## 결과 기록표 (복사해서 채우기)

```
환경: Kali ___ / Python ___ / Docker ___ / VPN ___ / LLM ___
P0 오프라인       ☐ 테스트 ___passed  ☐ 데모  ☐ 벤치
P1 doctor/LLM     ☐ 패널5  ☐ llm-test
P2 도구/VPN       ☐ 도구초록  ☐ tun0 ___________
P3 HTB 승인제     머신 ________  ☐ 포트  ☐ 열거  ☐ 리포트  ☐ 플래그출처______
P3b LLM           ☐ 라우팅요약
P4 docker 자율    ☐ egress  ☐ 스크립트실행  ☐ 범위밖차단
P5 vm 샌드박스    VM ________  ☐ 접속  ☐ 실행  ☐ confine
P6 라이브벤치     ☐ loopback ___/___  ☐ docker ___/___  ☐ 검증된풀이율____%
P7 산출물         ☐ 라이트업  ☐ 대시보드  ☐ 재생
특이사항: ________________________________________________
```

## 참고
- 운영·트러블슈팅 상세: [OPERATIONS.md](OPERATIONS.md) · 전체 사용법: [USAGE.md](USAGE.md)
- 구조·안전 모델: [ARCHITECTURE.md](ARCHITECTURE.md) · 연구 근거: [RESEARCH.md](RESEARCH.md)
- 이 런북은 **검증 절차**다. 실제 공격은 권한이 확인된 대상에서만.
