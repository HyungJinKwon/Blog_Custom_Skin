# HTB 머신 승인제 풀이 에이전트 — ROADMAP

> 레드팀 학습·모의해킹 연습용. **권한이 확인된 HTB(Hack The Box) 자산에 한정**해 동작한다.
> 이 문서는 요구사항·원칙을 유실 없이 추적하기 위한 단일 기준점이다.

---

## 0. 운영 원칙 (사용자 확정)

| # | 원칙 | 적용 |
|---|---|---|
| P1 | **라이트업 참조 금지** | 외부 walkthrough 검색·참조 금지. 사용자가 직접 제공한 자료만 허용 |
| P2 | **승인제(Human-in-the-loop)** | 에이전트는 *제안*만, 실행은 사용자 승인 후 |
| P3 | **빠른 진입 + 세부 정확 + 무오류 + 장기 유지** | 하드코딩 최소화, 런타임 탐지·설정화 |
| P4 | **팩트체크** | 추정을 사실로 단정하지 않음. `〔확인〕`/`〔추정〕` 태깅 |
| P5 | **자기 검증** | 이미 "확인"한 것도 재점검. 보수적 판단 |
| P6 | **다중 경로 검증** | 한 방법 실패로 단정 금지. 경우의 수를 돌림 |
| P7 | **실행 전 명령 검증** | 문법·형식 오류 없고 실행 가능한 명령만 실행 |

---

## 1. 아키텍처 — 실행 전 검증 파이프라인

```
LLM 제안
  │
  ├─[1] CommandValidator   : 쉘 문법 / base64·hex·10진수·포트 / 해시 형식 / 바이너리·파괴명령
  ├─[2] ScopeGuard         : 대상이 HTB 범위인지 (Target-Binding, 기본거부+승인확인)
  ├─[3] TargetProfiler     : Linux vs Windows-AD 판정 (증거기반, 확신도)
  └─[4] Approval           : 3분할 해설 + [1~3] 리포트 → 사용자 승인 → 실행
```

데이터 흐름: 관측(nmap 등) → **Compressor**(토큰 절감) → **Profiler/Orchestrator** → 제안 → 검증 → 승인 → 실행 → 관측.

---

## 2. 모듈 상태

| 모듈 | 파일 | 상태 |
|---|---|---|
| Scope Guard | `src/htb_agent/scope_guard.py` | ✅ Target-Binding 완료 (17 테스트) |
| Command Validator | `src/htb_agent/command_validator.py` | ✅ 완료 (감사 반영) |
| Target Profiler | `src/htb_agent/target_profiler.py` | ✅ 완료 (감사 반영) |
| 지식베이스(학습데이터) | `src/htb_agent/knowledge.py`, `knowledge/` | ✅ 완료 (사용자 규칙/노트로 성장) |
| 오케스트레이터 | `src/htb_agent/orchestrator.py` | ✅ 완료 (유한 단계 상태머신) |
| LLM 추상화 + 티어링 | `src/htb_agent/llm/` | ✅ 완료 (Claude/Ollama + Fake, 3관문 연동) |
| 관측 파서/압축기 | `src/htb_agent/observation/` | ✅ 완료 (nmap·HTTP·웹/SMB enum·압축·폴백) |
| 승인 루프 | `src/htb_agent/approval.py` | ✅ 완료 (3분할 해설) |

| 도구 레지스트리/설치 | `tools/registry.py`, `scripts/install_tools.sh` | ✅ 완료 (BloodHound·S3 등) |
| Recon 실행기(nmap) | `src/htb_agent/tools/recon.py` | ✅ 완료 (유한 폴백) |
| 환경 프리플라이트 | `src/htb_agent/environment.py` | ✅ 완료 (Kali) |
| CLI 진입점 | `src/htb_agent/main.py` | ✅ 완료 (Kali 실행) |
| 세션 상태 영속화 | `src/htb_agent/state.py` | ✅ 완료 (중단/재개, RECON 재사용) |

---

## 3. 환경 사실 〔확인, 실측〕

- 이 클라우드 세션: nmap/gobuster/ffuf/ssh **미설치**, VPN(tun) **없음**, 네트워크 가로채기로 "열림"이 **허상**.
  → **코드 작성·단위테스트 전용.** 실제 HTB 실행은 사용자의 Kali/Ubuntu + HTB VPN에서.
- HTB 대역(`10.10.10.0/23`, `10.129.0.0/16`)은 〔추정 — 통념〕. 런타임에 `tun0`로 실제 대역 탐지 + config 덮어쓰기.

---

## 4. 검증 한계 (과장 금지) 〔확인〕

- CommandValidator는 **형식적 무오류 + 실행 가능 형태**까지 보장. 도구별 옵션 의미, 해시의 "정답 여부"(평문 없이 불가)는 미보장 → 도구별 스펙 레이어로 확장.
- TargetProfiler는 **증거 기반 확신도**를 제공. 증거가 약하면 `〔추정〕`으로 표기하고 단정하지 않음.
