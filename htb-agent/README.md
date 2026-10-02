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

# 설정 파일 사용 / 중단 후 재개(RECON 재사용)
python3 -m htb_agent.main 10.129.1.5 --config ../config/config.example.json
python3 -m htb_agent.main 10.129.1.5 --resume
```

실행 파이프라인(유한 단계): **RECON → PROFILE → ENUM → (LLM) → VULN → REPORT**.
각 명령은 `검증 → 범위 → 승인` 3관문을 통과해야 실행됩니다.

### 학습데이터로 '성장' & 취약점 매핑

사용자 자료만 참조합니다(외부 라이트업 검색 없음). 파일을 추가할수록 똑똑해집니다.

- `knowledge/rules/*.json` : 관측(OS·포트·서비스)→다음 액션 규칙
- `knowledge/notes/*.md`   : 자유 노트(맥락)
- `knowledge/vulns/*.json` : 서비스+버전 → CVE/CWE 매핑

CVE/CWE 는 ① 도구 출력(nmap vuln·nikto 등)의 ID 추출 ② 버전 규칙 매핑으로 탐지되며,
익스플로잇은 자동실행하지 않고 **수동 제안**(searchsploit 등)으로 제시합니다.


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
| 무한루프 금지 | `tools/recon.py`·`orchestrator.py` — 유한 폴백/상한 + 에스컬레이션 |
| 라이트업 미참조 | 외부 walkthrough 검색 안 함. 사용자 제공 자료만 |
| 자동화 + 승인 | `orchestrator.py` — 단계 자동진행, 실행은 승인 게이트 |
| LLM 두뇌 | `llm/` — Claude/Ollama 교체 + 티어링, 출력은 3관문 통과 |
| 취약점 매핑 | `vuln.py` — CVE/CWE 추출 + 버전 규칙 매핑 |
| 성장(학습데이터) | `knowledge.py`·`knowledge/` — 사용자 규칙/노트 누적 |
| 중단/재개 | `state.py` — 상태 영속화, RECON 재사용 |
| 설정 | `config.py` — JSON/YAML, CLI>config>기본 |

세부 추적은 [`docs/ROADMAP.md`](docs/ROADMAP.md) 참고.

---

## 테스트

```bash
cd htb-agent
python3 tests/run_all.py          # 전체 스위트 일괄 실행·집계
# 개별:  python3 tests/test_<name>.py
```

현재 **13 스위트 228 테스트** 통과 (단위·회귀·통합). 네트워크/도구 없이도 러너
주입으로 전 로직 검증하며, 통합 테스트는 `main()` 을 엔드투엔드 구동합니다.

---

## 한계 (과장 금지)

- 명령 검증은 "형식적 무오류 + 실행 가능 형태"까지 보장. 도구별 옵션의 의미,
  해시의 정답 여부(평문 없이 불가)는 미보장.
- OS 판정은 증거 기반 확신도. 약한 증거는 `〔추정〕` 으로 표기.
- 실제 공격 실행·VPN 은 Kali 환경 전용. 개발용 클라우드 컨테이너에선 단위테스트만.
