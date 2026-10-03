# htb-agent — HTB 머신 승인제 자동 풀이 에이전트

레드팀 학습·모의해킹 연습용. **권한이 확인된 Hack The Box 머신에 한정**해 동작하는,
승인제(Human-in-the-loop) 자동 풀이 보조 에이전트.

> ⚠️ **대상 범위**: HTB VPN 으로 연결된 본인 계정 할당 머신만. 그 외 자산 사용 금지
> (Scope Guard 가 코드로 강제). 실제 공격 실행은 사용자 Kali + HTB VPN 환경에서.

---

## 진행 흐름 (모의해킹 단계 순서)

```
타겟 바인딩 → 정찰(RECON) → 식별(Linux/Win-AD) → 열거 → 초기 침투(user.txt)
          → 권한 상승(root.txt) → 측면 이동 → 취약점(CVE/CWE) → 리포트/라이트업
```

모든 실행 명령은 **① 검증 → ② 범위 → ③ 승인** 3관문을 통과해야 실행됩니다.
단계·라운드·명령 수에 상한이 있어 무한루프가 없습니다. 각 명령은 도구별로
**유효·안전한 옵션 조합 변형(경우의 수)** 을 몇 가지 더 시도해(`--variants`),
한 가지 방식만 보고 포기하지 않습니다 — 변형도 유한하며 3관문을 그대로 통과합니다.

구조·다이어그램·모듈 지도는 **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** 참고.

---

## 설치 (Kali / Ubuntu)

```bash
cd htb-agent
sudo ./scripts/install_tools.sh          # 보안 도구 전체(BloodHound·S3 등) / 또는: ... recon web smb ad
pip install -e .                         # 에이전트 설치 → 'htb-agent' 명령 생성
sudo openvpn your-htb.ovpn               # tun0 → 공격자 IP 자동탐지
```

Python 3.10+ (코어는 표준 라이브러리만, 외부 의존성 없음). LLM 사용 시 `pip install anthropic`(Claude) 또는 Ollama.

> 설치 없이 쓰려면 `cd htb-agent` 에서 `PYTHONPATH=src python3 -m htb_agent ...` 로 실행.

## 실행

설치(`pip install -e .`) 후에는 어디서나 `htb-agent` 명령을 쓸 수 있습니다.

```bash
# 승인제 포트스캔+열거 (명령마다 3분할 해설 + 승인)
htb-agent 10.129.1.5

# 범위내 자동승인 + 자격증명(→ 초기 침투·플래그 승격) + 라이트업 생성
htb-agent 10.129.1.5 --auto --cred administrator:Passw0rd --writeup

# 명령당 옵션 조합 변형(경우의 수) 수 조절 (기본 2, 1=변형끔)
htb-agent 10.129.1.5 --variants 3

# LLM 두뇌 / 중단 후 재개 / 설정 파일
htb-agent 10.129.1.5 --llm claude --llm-tier standard
htb-agent 10.129.1.5 --resume
htb-agent 10.129.1.5 --config config/config.example.json
```

전체 옵션: `htb-agent --help` (설치 전: `PYTHONPATH=src python3 -m htb_agent --help`).

---

## 핵심 특징

| 분류 | 내용 |
|---|---|
| 안전 | Target-Binding 범위강제 · 명령 검증(문법·base64·해시·포트·파괴명령) · 승인 게이트 |
| 관측 | nmap·HTTP·gobuster/ffuf/feroxbuster/nikto/whatweb·smbclient/smbmap/netexec·ldapsearch·dig/snmpwalk 파싱 |
| 식별 | Linux vs Windows-AD 증거기반 판정(확신도) |
| 지능 | 지식베이스(사용자 학습으로 성장) · 단계 순서 오케스트레이터 · 옵션 조합 변형(경우의 수) · LLM(Claude/Ollama, 캐싱·비용) |
| 목표 | CVE/CWE 탐지·매핑 · user.txt/root.txt 플래그 캡처 |
| 운영 | 중단/재개 · 크리덴셜 볼트 · 감사 로그 · 설정 파일 · 도구 설치 스크립트 |
| 산출 | 라이트업 자동 생성(htb-ctf-writeup-v5 / Tistory 13섹션) |

원칙: 승인제 · **외부 라이트업 미참조(사용자 자료만)** · 무한루프 금지 · 증거기반(〔확인〕/〔추정〕).

---

## 테스트

```bash
cd htb-agent && python3 tests/run_all.py     # 23 스위트 370 테스트
```

네트워크·도구 없이도 러너 주입으로 전 로직 검증. CI(GitHub Actions)가 push/PR 마다
테스트+컴파일(게이트) + ruff/mypy(비차단) 수행.

---

## 한계 (과장 금지)

- 명령 검증은 "형식적 무오류 + 실행 가능 형태"까지 보장(도구별 옵션 의미·해시 정답은 미보장).
- OS/취약점 판정은 증거기반 확신도 — 약하면 `〔추정〕` 표기.
- LLM 비용은 추정치. 실제 공격·VPN 은 Kali 환경 전용.
