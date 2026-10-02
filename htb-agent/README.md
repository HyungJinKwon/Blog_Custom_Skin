# HTB 머신 승인제 풀이 에이전트

레드팀 학습·모의해킹 연습용. **권한이 확인된 HTB(Hack The Box) 머신에 한정**해
동작하는, 승인제(Human-in-the-loop) 자동 풀이 보조 에이전트.

> ⚠️ **대상 범위**: HTB VPN 으로 연결된, 본인 계정에 할당된 머신만. 그 외
> 자산에 대한 사용은 금지입니다(Scope Guard 가 코드로 강제).

---

## 실행 환경 — Kali Linux (권장)

- **OS**: Kali Linux (또는 Debian 계열 Ubuntu)
- **Python**: 3.10+
- **네트워크**: HTB VPN(openvpn) 연결 → `tun0` 인터페이스
- **권한**: 일부 nmap 스캔(SYN 등)·responder 등은 root 필요

### 1) 도구 설치

```bash
cd htb-agent
sudo ./scripts/install_tools.sh            # 전체 (BloodHound·S3 등 포함)
# 또는 카테고리 선택:
sudo ./scripts/install_tools.sh recon web smb ad cloud
```

설치 확인:

```bash
python3 -c 'import sys; sys.path.insert(0,"src"); from htb_agent.tools.registry import report; print(report())'
```

### 2) HTB VPN 연결

```bash
sudo openvpn /path/to/your-htb.ovpn        # tun0 생성 → 공격자 IP 자동탐지됨
```

### 3) 실행

```bash
cd htb-agent/src
# 승인제 포트스캔 (각 명령마다 3분할 해설 + 승인 요청)
python3 -m htb_agent.main 10.129.1.5

# 범위내 자동승인(비대화형), 공격자 IP 수동 지정
python3 -m htb_agent.main 10.129.1.5 --auto --attacker-ip 10.10.14.5

# 허용 대역 커스텀 / 폴백 상한 조정
python3 -m htb_agent.main 10.129.1.5 --range 10.129.0.0/16 --max-attempts 3
```


### LLM 두뇌 (선택)

규칙기반(KB)만으로도 동작하지만, LLM 을 얹으면 관측·KB 를 근거로 다음 명령을
동적으로 추론합니다. LLM 제안도 **검증→범위→승인 3관문**을 그대로 통과해야 실행됩니다.

```bash
# Claude API (pip install anthropic; export ANTHROPIC_API_KEY=...)
python3 -m htb_agent.main 10.129.1.5 --llm claude --llm-tier standard

# 로컬 Ollama (ollama serve; 모델 pull)
python3 -m htb_agent.main 10.129.1.5 --llm ollama
```

티어: `cheap`(Haiku) / `standard`(Sonnet) / `strong`(Opus). 토큰 절감을 위해
관측은 압축 요약만 전달합니다.

---

## 설계 원칙

| 원칙 | 구현 |
|---|---|
| 권한 범위 강제 | `scope_guard.py` — Target-Binding, 범위밖 기본거부 |
| 승인제 | `approval.py` — 3분할 해설 + 사용자 승인 |
| 실행 전 검증 | `command_validator.py` — 문법·base64·해시·포트·파괴명령 |
| 정확한 관측 | `observation/` — nmap·HTTP 파싱(통째로 안 긁음) |
| OS 정확 식별 | `target_profiler.py` — Linux vs Windows-AD, 증거기반 확신도 |
| 무한루프 금지 | `tools/recon.py` — 유한 폴백 체인 + max_attempts + 에스컬레이션 |
| 라이트업 미참조 | 외부 walkthrough 검색 안 함. 사용자 제공 자료만 |

세부 추적은 [`docs/ROADMAP.md`](docs/ROADMAP.md) 참고.

---

## 테스트

```bash
cd htb-agent
for t in core scope observation tools recon; do python3 tests/test_$t.py; done
```

현재 **101 테스트** 통과 (단위·회귀). 네트워크/도구 없이도 러너 주입으로 전 로직 검증.

---

## 한계 (과장 금지)

- 명령 검증은 "형식적 무오류 + 실행 가능 형태"까지 보장. 도구별 옵션의 의미,
  해시의 정답 여부(평문 없이 불가)는 미보장.
- OS 판정은 증거 기반 확신도. 약한 증거는 `〔추정〕` 으로 표기.
- 실제 공격 실행·VPN 은 Kali 환경 전용. 개발용 클라우드 컨테이너에선 단위테스트만.
