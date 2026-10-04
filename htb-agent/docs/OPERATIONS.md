# ASSASSIN 실전 운영 가이드 (Kali)

> 권한이 확인된 대상(HTB·Dreamhack·CTF·인가된 진단)에서만 사용. 실제 공격/VPN 은
> 사용자 Kali 환경 전용. 데모(네트워크 없이 흐름 확인)는 `python3 scripts/demo.py`.
> 명령은 **`assassin`** (옛 `htb-agent` 도 동일하게 동작하는 별칭).

---

## 0. 완전 초보자 빠른 시작 (3단계)

```bash
# ① 설치
cd htb-agent && pip install -e . && sudo ./scripts/install_tools.sh

# ② 환경 점검 — 도구·VPN·LLM 이 준비됐는지 한눈에 (스캔 안 함)
assassin --doctor

# ③ 첫 실행 (초록불이면 바로)
assassin 10.129.1.5                 # HTB (VPN 연결 후)
assassin chall.site:1337 --platform ctf   # CTF/Dreamhack
```

`--doctor` 가 알려주는 대로 빠진 것만 채우면 됩니다. 막히면 아래 트러블슈팅(§4) 참고.

---

## 1. 빠른 시작

```bash
cd htb-agent
sudo ./scripts/install_tools.sh          # 보안 도구 일괄 설치(또는: ... recon web smb ad)
pip install -e .                         # 'assassin' / 'htb-agent' 명령 생성
sudo openvpn your-lab.ovpn               # tun0 → 공격자 IP 자동탐지
assassin 10.129.1.5                      # 승인제 포트스캔+열거 시작
```

설치 없이: `PYTHONPATH=src python3 -m htb_agent <target>`

---

## 2. 운영 흐름 (한눈에)

```
타겟 바인딩 → RECON(nmap -sC -sV) → 식별(Linux/Win-AD) → 열거(KB+LLM)
   → 초기침투(user) → 권한상승(root) → 측면이동 → 취약점(CVE/CWE 자동수집) → 리포트/라이트업
```

모든 실행 명령은 **① 검증 → ② 범위 → ③ 승인** 3관문 통과 후에만 실행된다.
단계·라운드·명령 수에 상한이 있어 무한루프가 없다.

---

## 3. 승인·플랫폼 모드

| 모드 | 명령 | 동작 |
|---|---|---|
| 스마트(기본) | `assassin <t>` | 범위내+검증통과 자동실행 · 파괴명령 자동거부 · 범위밖만 사람확인 |
| 완전자동 | `assassin <t> --auto` | 범위밖은 조용히 건너뜀(무프롬프트) |
| 완전수동 | `assassin <t> --manual` | 모든 명령 실행 전 확인 |

| 플랫폼 | 명령 | 특징 |
|---|---|---|
| HTB(기본) | `--platform htb` | VPN 대역 강제 · boot2root(user/root, 32-hex/HTB{}) |
| Dreamhack/CTF | `--platform dreamhack` / `ctf` | 단일 타겟(host:port/URL) · Jeopardy 단일 플래그(flag{}/DH{}) |

LLM 두뇌(선택): `--llm hybrid`(Ollama+Claude 라우팅/폴백) · `--llm claude` · `--llm ollama`.
CVE 자동수집: 기본 활성(NVD/GitHub) · 끄기 `--no-enrich` · 오프라인 `--offline`.

---

## 4. 트러블슈팅

### 4.1 공격자 IP(tun0) 미탐지
- 증상: "공격자 IP 자동탐지 실패".
- 조치: VPN 연결 확인(`ip a show tun0`) 후 `--attacker-ip <VPN IP>` 로 수동 지정.

### 4.2 범위 위반(ScopeViolation)
- 증상: 명령이 대상 외 IP/호스트를 포함해 거부됨.
- 원인(설계): Scope Guard 가 바인딩된 타겟/대역 밖 통신을 코드로 차단.
- 조치: HTB 는 허용대역(`--range`) 확인. CTF/Dreamhack 은 `--platform` 지정으로
  단일 타겟 바인딩(대역 강제 해제, host:port/URL 허용).

### 4.3 도구 미설치(NO_BINARY 경고)
- 증상: `'<도구>' 미설치 — 실행환경(Kali)에서 확인 필요`.
- 조치: `sudo ./scripts/install_tools.sh [카테고리]`. 카테고리:
  `recon web smb ad creds cloud traffic re pwn forensic pivot`.

### 4.4 LLM 백엔드 사용 불가
- 증상: `hybrid 사용 불가: ollama(Connection refused) / claude(anthropic SDK 미설치)`.
- 먼저: `assassin --doctor` 로 어느 백엔드가 왜 안 되는지 확인(복붙 설치 힌트 제공).
- 일괄 설치: `sudo ./scripts/install_tools.sh llm` (anthropic 설치 + ollama 안내).
- 조치: Claude=`pip install anthropic` + `export ANTHROPIC_API_KEY=sk-...`.
  Ollama=`ollama serve` + `ollama pull llama3.1:8b`(다른 모델은 `export OLLAMA_MODEL=...`,
  원격 서버는 `export OLLAMA_HOST=http://ip:11434`).
- 둘 중 하나만 있어도 hybrid 가 단일 백엔드로 동작. LLM 없이도 규칙기반(`--llm none`,
  기본값)으로 완전 동작.

### 4.5 CVE 자동수집이 비어 있음
- 원인: `--offline`/`--no-enrich`, 네트워크 차단, 또는 캐시 없음.
- 조치: 온라인에서 1회 실행 시 `<knowledge>/cve_cache` 에 캐시됨. 이후 오프라인 재사용.

### 4.6 중단 후 재개
- `--resume`: 저장된 상태의 RECON 결과를 재사용(재스캔 생략). `--no-save` 로 저장 끔.

---

## 5. 지식베이스로 '성장'시키기

에이전트는 외부 라이트업을 검색하지 않는다(P1). 대신 사용자가 넣은 자료로 제안이 풍부해진다.

- 규칙: `knowledge/rules/*.json` — `{"name","when":{os,ports,services},"suggest":[...],"phase"}`
- 취약점: `knowledge/vulns/*.json` — `{"name","service","version_contains","cve","cwe","suggest"}`
- 노트: `knowledge/notes/*.md` — 자유 서술(맥락).

동봉 공개지식(출처 NVD/MITRE): `vulns/common-services.json`, `rules/linux-privesc.json`,
`rules/windows-privesc.json`. 자세한 방법론은 `knowledge/notes/privesc-and-cves-methodology.md`.

---

## 6. 산출물

- 라이트업: `--writeup`(htb-ctf-writeup-v5) · `--writeup-format tistory`(13섹션).
  CVE 레퍼런스(NVD/CVSS/PoC)·블루팀 탐지지표(SIEM/Snort/Wireshark)가 자동 포함된다.
- 결과 내보내기: `--json`(기계판독, 외부 도구·파이프라인 연계) · `--html`(블루/네이비
  대시보드, 외부 의존 0). 경로 생략 시 `<state-dir>/report_<타겟>.{json,html}`.
- 감사 로그(JSONL): 기본 `<state-dir>/audit_<타겟>.jsonl` · 끄기 `--no-audit`.

---

## 7. 안전 수칙 (요약)

- 권한이 확인된 자산만. 범위 밖 금지(코드로 강제).
- 익스플로잇·권한상승 명령은 '탐지 + 수동 제안'까지만 자동화 — 실행은 승인·판단.
- 과장 금지: OS/취약점 판정은 증거기반 확신도, 약하면 `〔추정〕` 표기.
