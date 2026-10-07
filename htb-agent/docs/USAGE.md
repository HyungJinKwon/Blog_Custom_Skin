# ASSASSIN 전체 사용법

> 승인제 자동 풀이 에이전트(HTB · Dreamhack · CTF)의 설치부터 운영·지식 관리·유지보수까지 한 문서로 정리했다.
> 명령은 `assassin`(옛 이름 `htb-agent` 도 같은 별칭). 설치 없이 쓸 때는 `htb-agent/` 에서 `PYTHONPATH=src python3 -m htb_agent ...`.
>
> ⚠️ **권한이 확인된 대상에서만 사용한다**(대회·플랫폼이 명시한 대상, 인가된 진단). 범위 밖 통신은 Scope Guard 가 코드로 막는다.

---

## 목차

1. [한눈에 보기](#1-한눈에-보기)
2. [설치](#2-설치)
3. [첫 실행 3단계](#3-첫-실행-3단계)
4. [실행 흐름과 3관문](#4-실행-흐름과-3관문)
5. [승인 모드 고르기](#5-승인-모드-고르기)
6. [플랫폼별 사용법](#6-플랫폼별-사용법)
7. [자격증명 넣기](#7-자격증명-넣기)
8. [LLM 두뇌 붙이기](#8-llm-두뇌-붙이기)
9. [지식베이스: 시작 지식 · 학습 · 공유 · 자동 반영](#9-지식베이스-시작-지식--학습--공유--자동-반영)
10. [자동 준비 도구(생성 전용)](#10-자동-준비-도구생성-전용)
11. [산출물: 라이트업 · 리포트 · 로그 · 재개](#11-산출물-라이트업--리포트--로그--재개)
12. [설정 파일](#12-설정-파일)
13. [한도와 튜닝](#13-한도와-튜닝)
14. [환경변수](#14-환경변수)
15. [데모](#15-데모)
16. [상황별 레시피](#16-상황별-레시피)
17. [트러블슈팅](#17-트러블슈팅)
18. [유지보수자용](#18-유지보수자용)
19. [파일 위치 지도](#19-파일-위치-지도)

---

## 1. 한눈에 보기

| 항목 | 내용 |
|---|---|
| 무엇 | 타겟 하나를 받아 정찰 → 식별 → 열거 → 침투 → 권한상승 → 리포트까지 단계 순서로 추진하는 보조 에이전트 |
| 대상 | HTB(boot2root) · Dreamhack/CTF(Jeopardy 단일 플래그) |
| 안전 | 모든 명령은 **① 검증 → ② 범위 → ③ 승인** 을 통과해야 실행. 범위 밖·파괴 명령·동적 코드 실행은 자동 실행하지 않음 |
| 지능 | 규칙 기반(기본) + 지식베이스(RAG) + 선택형 LLM(Claude / Ollama / hybrid) |
| 지식 | 59개 주제 번들 시드로 누구나 같은 지식으로 시작 → 학습으로 성장 → 검증 후 모두에게 자동 공유 |
| 산출 | 라이트업(HTB v5 / Tistory 13섹션) · JSON · HTML 대시보드 · 감사 로그 |
| 의존성 | Python 3.10+ 표준 라이브러리만(LLM 사용 시에만 추가 설치) |

원칙: 승인제 · 외부 라이트업 미참조(사용자 자료·권위 출처만) · 무한루프 없음(모든 반복에 상한) · 증거 기반 판정(약하면 〔추정〕).

---

## 2. 설치

### 2.1 Kali / Ubuntu

```bash
git clone https://github.com/HyungJinKwon/HTB_AUTO_AGENT.git
cd HTB_AUTO_AGENT/htb-agent
sudo ./scripts/install_tools.sh          # 보안 도구 일괄 설치
pip install -e .                         # 'assassin' 명령 생성
sudo openvpn your-htb.ovpn               # (HTB) tun0 → 공격자 IP 자동탐지
```

| 명령 | 바이너리 | 옵션 | 파라미터 |
|---|---|---|---|
| `sudo ./scripts/install_tools.sh recon web` | `install_tools.sh` | (없음) | 설치할 카테고리. 생략 시 전체 |
| `pip install -e .` | `pip` | `-e`: 편집 가능 설치(소스 수정이 바로 반영) | `.`: 현재 디렉토리 패키지 |
| `sudo openvpn your-htb.ovpn` | `openvpn` | (없음) | 플랫폼에서 받은 VPN 설정 파일 |

설치 카테고리: `recon` `web` `smb` `ad` `creds` `cloud` `traffic` `re` `pwn` `forensic` `pivot` `llm`

### 2.2 설치 없이 실행

```bash
cd htb-agent
PYTHONPATH=src python3 -m htb_agent --help
```

### 2.3 업데이트

```bash
git pull                                  # 코드 + 번들 시드 최신화
```

> 지식(시드)만은 git pull 없이도 실행 시 하루 1회 자동으로 최신화된다(§9.6).

---

## 3. 첫 실행 3단계

```bash
assassin --doctor                         # ① 환경 점검(도구·VPN·LLM) — 스캔 안 함
assassin 10.129.1.5                       # ② HTB 타겟 실행(스마트 승인)
assassin 10.129.1.5 --writeup --html      # ③ 라이트업 + HTML 대시보드까지
```

| 명령 | 바이너리 | 옵션 | 파라미터 |
|---|---|---|---|
| `assassin --doctor` | `assassin` | `--doctor`: 자가진단만 하고 종료 | — |
| `assassin 10.129.1.5` | `assassin` | (기본 = 스마트 승인) | 타겟 IP(HTB 는 VPN 대역만 허용) |
| `assassin 10.129.1.5 --writeup --html` | `assassin` | `--writeup`: 라이트업 MD 생성 · `--html`: 대시보드 생성 | 경로 생략 시 기본 위치(§11) |

`--doctor` 가 빨간 항목을 알려주면 그것만 채우면 된다.

---

## 4. 실행 흐름과 3관문

```
타겟 바인딩 → 정찰(RECON) → 식별(Linux / Windows-AD) → 열거 → 초기 침투(user)
          → 권한 상승(root) → 측면 이동 → 취약점(CVE/CWE) → 리포트 / 라이트업
```

모든 명령이 실행 전에 거치는 관문:

| 관문 | 하는 일 | 걸리면 |
|---|---|---|
| ① 검증 | 문법·인코딩·포트·파괴 명령·위험 패턴 검사 | 자동 거부 |
| ② 범위 | 명령 안의 모든 호스트/IP 가 바인딩된 타겟·공격자 IP 인지 확인(비정규 숫자 표기·IPv6 포함) | 확인 필요(자동 실행 안 함) |
| ③ 승인 | 승인 모드에 따라 자동/사람 확인 | 모드별 처리(§5) |

- 범위 안이라도 **동적·원격 코드 실행**(파이프→셸, `eval`, `IEX`, 명령 치환 등)은 사람 검토로 넘어간다. 프롬프트에 `▲ … 포함 — 내용 확인 후 실행? [y/N]` 로 표시된다.
- 단계·라운드·명령 수·스윕 횟수에 모두 상한이 있어 무한루프가 없다(§13).
- 같은 목적의 명령을 도구별 안전한 옵션 조합으로 몇 가지 더 시도한다(`--variants`, 기본 2).

---

## 5. 승인 모드 고르기

| 모드 | 명령 | 범위 안 + 검증 통과 | 범위 밖 | 동적 코드 실행 | 언제 |
|---|---|---|---|---|---|
| 스마트(기본) | `assassin <t>` | 자동 실행 | 사람 확인 | 사람 확인 | 평소 |
| 완전 자동 | `--auto` | 자동 실행 | 조용히 건너뜀 | 수동 제안으로 강등 | 무인 실행·배치 |
| 완전 수동 | `--manual` | 사람 확인 | 사람 확인 | 사람 확인 | 수업·검토·민감 환경 |
| 능동적 완전자동 | `--autonomous`(=`--hackathon`) | 자동 실행 + 깊은 스윕·병렬 열거·변형 학습·자동 학습 | 실행 안 함 | 수동 제안으로 강등 | 해커톤·시간 제한 대회 |

- `--manual` 은 `--autonomous` 보다 우선한다.
- 사람 확인 프롬프트는 `실행할까요? [y/N]` — 엔터만 치면 **실행 안 함**(N 기본).

---

## 6. 플랫폼별 사용법

### 6.1 HTB(기본)

```bash
assassin 10.129.1.5
assassin 10.129.1.5 --attacker-ip 10.10.14.5      # tun0 자동탐지가 안 될 때
assassin 10.129.1.5 --range 10.129.0.0/16         # 허용 대역 직접 지정
```

- VPN 대역을 강제한다. 플래그: `user.txt` / `root.txt`(32-hex, `HTB{}`).

### 6.2 Dreamhack

```bash
assassin web-chall.dreamhack.games:8080 --platform dreamhack
assassin chall.dreamhack.io:8080 --platform dreamhack --category pwn --llm hybrid
```

### 6.3 CTF

```bash
assassin http://ctf.example.com/chall --platform ctf --flag-prefix myctf
```

| 옵션 | 설명 |
|---|---|
| `--platform {htb,dreamhack,ctf}` | dreamhack/ctf 는 단일 타겟(host:port/URL) 바인딩 + 단일 플래그 모드 |
| `--category {web,pwn,rev,crypto,forensic,misc}` | LLM 제안을 카테고리에 맞게 유도 |
| `--flag-prefix TAG` | 우선 인식할 플래그 접두(반복 가능). `DH{}` `flag{}` `CTF{}` 등 `TAG{}` 는 기본 자동 인식 |

---

## 7. 자격증명 넣기

`--cred` 를 주면 `{user}` `{pass}` `{domain}` `{hash}` 가 들어간 제안이 실행 후보로 승격된다(반복 가능).

| 형식 | 예 |
|---|---|
| `user:pass` | `--cred admin:Passw0rd` |
| `user:pass:domain` | `--cred svc:Summer2024:corp.htb` |
| `user:pass:domain:nthash` | `--cred svc:x:corp.htb:<32hex>` |
| Pass-the-Hash | `--cred administrator:<32hex>` 또는 `--cred administrator::corp.htb:<NT 또는 LM:NT>` |

```bash
assassin 10.129.1.5 --auto --cred administrator:Passw0rd --writeup
```

---

## 8. LLM 두뇌 붙이기

LLM 없이도(`--llm none`, 기본) 규칙 기반으로 완전 동작한다. 붙이면 열거·분석 제안이 풍부해진다.

| 백엔드 | 명령 | 준비 |
|---|---|---|
| Claude | `--llm claude` | `pip install anthropic` + `export ANTHROPIC_API_KEY=...` |
| Ollama(로컬) | `--llm ollama` | `ollama serve` + `ollama pull llama3.1:8b` |
| hybrid | `--llm hybrid` | 위 둘 중 하나 이상. 단계 난이도로 라우팅하고 실패 시 폴백 |

- 비용/성능: `--llm-tier {cheap,standard,strong}`(기본 standard). 어려운 단계에서 자동 승격된다.
- 일괄 준비: `sudo ./scripts/install_tools.sh llm`
- LLM 출력도 3관문을 그대로 통과해야 실행된다.

---

## 9. 지식베이스: 시작 지식 · 학습 · 공유 · 자동 반영

### 9.1 구조

```
knowledge/
├── rules/*.json            서비스·OS별 점검 규칙(제안 명령)
├── vulns/*.json            배너/버전 기반 CVE 지식
├── notes/                  자유 노트(RAG 로 풀이 중 참조)
│   ├── learned/seed-*.md   ★ 번들 시드(저장소에 포함, 모두 동일한 시작 지식)
│   ├── learned/learned-*.md  내가 학습한 노트(로컬, git 추적 안 함)
│   └── ingested/           내가 넣은 자료(로컬)
├── shared_seeds/           공유 저장소 최신 시드 캐시(로컬, 자동 동기화)
└── cve_cache/              CVE 수집 캐시(로컬)
```

### 9.2 지식이 자라는 전체 흐름

```
① 번들 시드(59개 주제)  ── 누구나 clone 즉시 같은 지식으로 시작(오프라인 포함)
        │
② 각자 학습  ── --learn / --learn-gaps / --web-learn / --ingest  → 내 로컬에만 쌓임
        │
③ 승격(공유)  ── 매주 자동: 학습 → 품질 관문 → 전체 테스트 → PR → 자동 병합
        │
④ 로컬 반영  ── 에이전트 실행 시 하루 1회 자동 동기화(검증 통과분만)
        ▼
  모두의 시작 지식이 함께 커짐
```

### 9.3 학습하기(내 로컬)

| 명령 | 하는 일 |
|---|---|
| `assassin --learn list` | 학습 가능한 주제 목록 |
| `assassin --learn kerberoasting` | 한 주제를 권위 출처(MITRE ATT&CK·OWASP·PortSwigger·RFC 등)에서 학습 |
| `assassin --learn all` | 59개 주제 전체를 한 번에 학습 |
| `assassin --ingest ./my-writeups/` | 내 자료(.md/.txt/.pdf)를 노트로 학습. 본인 자료는 풀이 중 참조 허용 |
| `assassin <t> --learn-gaps` | 풀이 중 모르는 기술을 만나면 권위 출처에서 자동 학습(autonomous 기본) |
| `assassin <t> --web-learn` | 카탈로그 밖 공백을 인터넷 검색으로 학습. HTB 라이트업은 출처 불문 차단, 교차검증 통과분만(autonomous 기본) |

- 학습 내용은 노트로만 저장된다(실행·명령화하지 않음).
- 오프라인이면 출처 포인터만 남고, 시작 지식은 번들 시드가 보장한다.

### 9.4 승격(공유) — 보통은 자동, 손으로도 가능

품질 관문(하나라도 걸리면 승격 안 함):

| 관문 | 기준 |
|---|---|
| 출처 | 허용(권위) 도메인 + 해당 주제의 현재 카탈로그에 있는 출처 |
| 요약 | 120자 이상(승격 시 500자로 정리) |
| 잡음 | 쿠키·JavaScript 안내·사이트 공지 등 웹페이지 군더더기 없음 |
| 라이트업 | HTB 라이트업 신호 없음 |
| 형식 | 제어문자 없음 |

규칙: 사람이 다듬은 시드 본문은 그대로 두고 `## 최신 보강(승격)` 섹션에만 쓴다. 같은 출처는 교체되고 주제당 3건까지만 둔다. 카탈로그에서 빠진 출처의 승격분은 정리하며, 내용이 같으면 처음 승격일을 유지한다.

손으로 할 때(유지보수자·기여자):

```bash
assassin --learn all
assassin --promote all                       # 또는 --promote sqli
git diff knowledge/notes/learned/seed-*.md   # 검토
# → 커밋 → PR → CI 통과 → 병합
```

### 9.5 공유 저장소 자동 반영(주간)

GitHub Actions **`KB 자동 승격`** (`.github/workflows/kb-auto-promote.yml`)

| 항목 | 내용 |
|---|---|
| 일정 | 매주 월요일 03:17(KST). Actions 탭에서 **Run workflow** 로 수동 실행 가능 |
| 순서 | `--learn all` → `--promote all` → 시드 변경 확인 → 전체 테스트 + 컴파일 → PR `kb/auto-promote` 생성 → 자동 병합 |
| 변경 없음 | 테스트·PR 단계 건너뜀(정상) |
| 실패 | Actions 탭에 빨간 표시. 기존 시드는 그대로 |

필요한 저장소 설정(1회): Settings → Actions → General → Workflow permissions → **Read and write permissions** + **Allow GitHub Actions to create and approve pull requests**.

### 9.6 로컬 자동 반영(하루 1회)

타겟을 실행하면 공유 저장소의 시드 목록을 조회해 **로컬과 다른 것만** 받고, 아래 검증을 모두 통과한 것만 `knowledge/shared_seeds/` 캐시에 적용한다. 지식베이스는 캐시본을 우선 사용한다.

| 검증 | 내용 |
|---|---|
| 형식 | 시드 파일명 · UTF-8 · 제어문자 없음 · 650B 이상 6000자 이하 |
| 내용 | 필수 5개 섹션(개요·핵심 기법·표준 도구·블루팀 탐지·완화) · 권위 출처 URL |
| 승격분 | 승격 관문 통과 · 주제당 3건 이하 |
| 무결성 | 내용 해시 = 목록 해시 · 다운로드 주소 = 이 저장소 raw 주소 |

안전 장치:
- 데이터(노트)만 받고 코드·규칙은 받지 않는다.
- git 추적 파일을 건드리지 않으므로 git pull 충돌이 없다.
- 내가 편집 중인(미커밋) 시드는 덮어쓰지 않는다.
- git pull 로 시드가 바뀌면 해당 캐시본은 자동으로 무시한다.
- 오프라인이면 조용히 건너뛰고, 하루 1회만 재시도한다.

| 명령 | 동작 |
|---|---|
| `assassin --kb-sync` | 지금 바로 동기화하고 결과 출력 |
| `assassin <t> --no-kb-sync` | 이번 실행만 끄기 |
| `export ASSASSIN_NO_KB_SYNC=1` | 항상 끄기 |
| `assassin <t> --offline` | 네트워크 수집 전부 끄기(동기화 포함) |

---

## 10. 자동 준비 도구(생성 전용)

풀이 중 조건이 갖춰지면 자동으로 생성되어 리포트·라이트업·JSON/HTML 에 포함된다. 단독 실행도 가능하다. **실행은 하지 않는다** — 권한 확인 대상에서 사용자가 직접 판단해 쓴다.

| 도구 | 단독 실행 | 자동 생성 조건 | 생성물 |
|---|---|---|---|
| 리버스쉘 | `assassin --revshell 10.10.14.5:4444` | 공격자 IP 확보(리스너 포트 `--lport`, 기본 4444) | bash/nc/python3/php/powershell/socat 페이로드 + 리스너·안정화 힌트 |
| AWS/S3 | `assassin --cloud acme.htb` | 호스트명/도메인 확보 | 버킷명 후보 + 비인증 점검 명령 |
| 권한상승 | `assassin --privesc linux` | OS 식별 | sudo·SUID·capabilities·cron·커널·토큰·서비스 점검 + LPE 후보 |
| 해시 크래킹 | `assassin --crack '$krb5tgs$23$...'` | 출력·자격증명에서 해시 발견 | 해시 종류 식별 + john/hashcat 명령(모드·포맷·워드리스트) |

---

## 11. 산출물: 라이트업 · 리포트 · 로그 · 재개

| 산출물 | 옵션 | 기본 위치 |
|---|---|---|
| 라이트업(HTB v5) | `--writeup [경로]` | `writeup_<타겟>.md` |
| 라이트업(Tistory 13섹션) | `--writeup --writeup-format tistory` | 위와 같음 |
| JSON 리포트 | `--json [경로]` | `<state-dir>/report_<타겟>.json` |
| HTML 대시보드 | `--html [경로]` | `<state-dir>/report_<타겟>.html` |
| 감사 로그(JSONL) | `--log-file 경로` / 끄기 `--no-audit` | `<state-dir>/audit_<타겟>.jsonl` |
| 세션 상태 | `--state-dir 경로` / 끄기 `--no-save` | `./state` |

- 라이트업에는 CVE 레퍼런스(NVD·CVSS·PoC)와 블루팀 탐지 지표(SIEM·Snort·Wireshark)가 자동으로 들어간다.
- HTML 상단 "한눈에 보기"에는 3관문 지표·플래그 출처·지식 기반(시작 지식 커버·승격 발췌·공유 동기화·이번 세션 자율 학습과 공백)·안전 경계·단계 진행이 요약된다(발표·심사용).
- 중단 후 재개: `assassin <t> --resume` — 저장된 RECON 결과를 재사용해 재스캔을 생략한다.

---

## 12. 설정 파일

우선순위: **CLI > 설정 파일 > 기본값**

```bash
assassin 10.129.1.5 --config config/config.example.json
```

```json
{
  "platform": "htb",
  "allowed_ranges": ["10.129.0.0/16"],
  "attacker_ips": [],
  "llm": {"backend": "none", "tier": "standard"},
  "max_attempts": 4,
  "max_enum": 6,
  "max_llm": 5,
  "max_rounds": 2,
  "max_sweeps": 2,
  "max_parallel": 1,
  "max_variants": 2,
  "knowledge_dir": "knowledge",
  "state_dir": "state"
}
```

- YAML(`config/config.example.yaml`)도 지원한다.
- 알 수 없는 키는 경고와 함께 무시된다.
- 개인 설정은 `config/config.yaml` 에 두면 git 에 올라가지 않는다.

---

## 13. 한도와 튜닝

| 옵션 | 기본 | autonomous 기본 | 의미 |
|---|---|---|---|
| `--max-attempts` | 4 | 4 | 포트스캔 폴백 최대 시도 |
| `--max-enum` | 6 | 10 | 열거 자동 실행 최대 개수 |
| `--max-rounds` | 2 | 3 | 열거/LLM 반복 라운드 |
| `--max-sweeps` | 2 | 3 | 새 관측·자격증명으로 이전 단계 재진입하는 횟수(정체 시 조기 종료) |
| `--max-parallel` | 1 | 4 | 열거 명령 동시 실행 수(I/O 만 병렬, 관문·결과 처리는 순차) |
| `--variants` | 2 | 3 | 명령당 옵션 조합 변형 수(1 = 변형 끔) |
| `--no-enrich` | — | — | CVE/CWE 자동 수집(NVD·GitHub) 끄기 |
| `--enrich-cache 경로` | `<knowledge>/cve_cache` | — | CVE 캐시 위치 |
| `--knowledge 경로` | `./knowledge` | — | 지식베이스 위치 |

---

## 14. 환경변수

| 변수 | 용도 |
|---|---|
| `ANTHROPIC_API_KEY` | Claude 백엔드 API 키 |
| `OLLAMA_HOST` | Ollama 서버 주소(기본 `http://localhost:11434`) |
| `OLLAMA_MODEL` | 모든 tier 에 쓸 Ollama 모델 이름(미설정 시 cheap/standard `llama3.1:8b`, strong `llama3.1:70b`) |
| `ASSASSIN_NO_KB_SYNC` | `1` 이면 실행 시 공유 시드 자동 동기화 끄기 |
| `ASSASSIN_KB_SYNC_REPO` | 동기화할 공유 저장소(`owner/repo`, 기본 `HyungJinKwon/HTB_AUTO_AGENT`) — 포크 운영 시 |
| `ASSASSIN_KB_SYNC_REF` | 동기화할 브랜치/태그(생략 시 저장소 기본 브랜치) |
| `NO_COLOR` / `FORCE_COLOR` | 터미널 색 끄기 / 강제 켜기(비-TTY·파이프에서는 자동으로 꺼짐) |

---

## 15. 데모

네트워크·실제 도구 없이 전체 흐름을 볼 수 있다.

```bash
cd htb-agent
python3 scripts/demo.py                    # 전체 흐름 요약
python3 scripts/demo.py --live             # 발표용 6단계 시연(범위 밖 거부 → 정찰·식별 → 열거 → 3관문 → 지식 → 산출)
python3 scripts/demo.py --live --pace 2    # 단계 사이 2초 멈춤
python3 scripts/demo.py --write out/       # 라이트업·JSON·HTML 파일 저장
```

---

## 16. 상황별 레시피

### 16.1 해커톤 대회(시간 제한, 최대 자율)

```bash
assassin --doctor
assassin 10.129.1.5 --autonomous --llm hybrid --writeup --html
```

### 16.2 교육·수업(모든 명령을 보며 설명)

```bash
assassin 10.129.1.5 --manual --writeup --writeup-format tistory
python3 scripts/demo.py --live --pace 3      # 강의 도입부 시연
```

### 16.3 Dreamhack 웹 문제

```bash
assassin chall.dreamhack.io:8080 --platform dreamhack --category web --llm hybrid --html
```

### 16.4 인터넷이 막힌 환경

```bash
assassin 10.129.1.5 --offline                # CVE 수집·학습·동기화 모두 끔(번들 시드로 동작)
```

### 16.5 시작 전에 지식 최신화

```bash
assassin --kb-sync                           # 공유 저장소 최신 시드 받기
assassin --ingest ./my-notes/                # 내 자료 추가
```

### 16.6 결과를 다른 도구로 넘기기

```bash
assassin 10.129.1.5 --auto --json out/result.json
```

---

## 17. 트러블슈팅

| 증상 | 원인 | 조치 |
|---|---|---|
| 공격자 IP 자동탐지 실패 | VPN 미연결 | `ip a show tun0` 확인 후 `--attacker-ip <VPN IP>` |
| ScopeViolation(범위 위반) | 타겟/대역 밖 주소 포함(설계상 차단) | HTB 는 `--range` 확인, CTF/Dreamhack 은 `--platform` 지정 |
| `'<도구>' 미설치` | 도구 없음 | `sudo ./scripts/install_tools.sh <카테고리>` |
| `hybrid 사용 불가` | LLM 백엔드 미준비 | `assassin --doctor` → §8 준비. LLM 없이도 동작 |
| CVE 정보가 비어 있음 | 오프라인·`--no-enrich`·캐시 없음 | 온라인에서 1회 실행해 캐시 생성 |
| `공유 시드 동기화 실패` | 오프라인·차단·저장소 비공개 | 무시해도 됨(기존 시드로 동작). 즉시 재시도는 `assassin --kb-sync` |
| `✗ seed-x.md — 로컬 수정본(미커밋) 보존` | 내가 편집 중인 시드 | 의도된 동작. 커밋하거나 되돌리면 다음 동기화부터 반영 |
| 주간 워크플로가 PR 단계에서 실패 | Actions 권한 미설정 | §9.5 저장소 설정 확인 |
| 프롬프트에서 멈춘 것 같음 | 사람 확인 대기(`[y/N]`) | `y` 실행 / 엔터 건너뜀. 무인 실행은 `--auto` |

더 자세한 운영 가이드: [OPERATIONS.md](OPERATIONS.md)

---

## 18. 유지보수자용

### 18.1 테스트

```bash
cd htb-agent
python3 tests/run_all.py                          # 전체 스위트(네트워크·도구 없이)
python3 tests/test_kb_sync.py                     # 개별 스위트
python3 -m py_compile src/htb_agent/*.py src/htb_agent/*/*.py
python3 scripts/gen_cli_docs.py --check           # README CLI 표가 최신인지
```

### 18.2 CI

| 워크플로 | 트리거 | 내용 |
|---|---|---|
| `htb-agent CI` | `htb-agent/**` push/PR | Python 3.10~3.13 테스트 + 컴파일(게이트), ruff·mypy(비차단) |
| `KB 자동 승격` | 매주 월 03:17 KST · 수동 | §9.5 |

CI 가 강제하는 지식 불변식:
- 모든 주제에 시드가 있고 필수 섹션·권위 출처를 갖춘다.
- 커밋된 승격분은 관문을 통과하고, 출처가 카탈로그에 있으며, 주제당 3건 이하다.
- 커밋된 시드는 모두 로컬 동기화 검증을 통과한다.

### 18.3 학습 출처(카탈로그) 바꾸기

1. `src/htb_agent/learn.py` 의 `SOURCES` 에서 주제의 `(제목, URL)` 을 수정한다. 허용 도메인은 `ALLOWED_DOMAINS`.
2. `assassin --learn <주제>` → `assassin --promote <주제>` → `git diff` 로 확인한다.
3. 커밋 → PR. 빠진 출처의 옛 승격분은 promote 가 정리한다.

### 18.4 CLI 옵션을 추가했다면

```bash
python3 scripts/gen_cli_docs.py                   # README 의 전체 CLI 옵션 표 재생성
```

---

## 19. 파일 위치 지도

| 경로 | 내용 |
|---|---|
| `htb-agent/src/htb_agent/main.py` | CLI 진입점 |
| `.../scope_guard.py` · `command_validator.py` · `approval.py` | 3관문(범위·검증·승인) |
| `.../orchestrator.py` | 단계 순서 실행·스윕·병렬 열거 |
| `.../knowledge.py` | 지식베이스 로드·RAG |
| `.../learn.py` · `promote.py` · `kb_sync.py` | 학습 · 승격 · 로컬 자동 동기화 |
| `htb-agent/knowledge/` | 규칙·취약점·노트·시드 |
| `htb-agent/config/` | 설정 예시 |
| `htb-agent/scripts/` | 도구 설치 · 데모 · CLI 문서 생성 |
| `htb-agent/docs/` | 이 문서 · [ARCHITECTURE.md](ARCHITECTURE.md) · [OPERATIONS.md](OPERATIONS.md) |
| `.github/workflows/` | CI · 주간 자동 승격 |

전체 CLI 옵션 표(자동 생성): [README.md#전체-cli-옵션](../README.md#전체-cli-옵션)
