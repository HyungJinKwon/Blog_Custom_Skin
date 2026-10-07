# ASSASSIN — 승인제 자동 풀이 에이전트 (HTB · Dreamhack · CTF)

```
▄▀█ █▀ █▀ ▄▀█ █▀ █▀ █ █▄░█
█▀█ ▄█ ▄█ █▀█ ▄█ ▄█ █ █░▀█
```

레드팀 학습·모의해킹·CTF 연습용. **권한이 확인된 대상에 한정**해 동작하는,
승인제(Human-in-the-loop) 자동 풀이 보조 에이전트. **명령은 `assassin`** (`htb-agent` 는 하위호환 별칭).

**플랫폼 프로파일** `--platform {htb,dreamhack,ctf}`:
- `htb` (기본): HTB VPN 대역 강제 · boot2root(user.txt/root.txt, 32-hex/HTB{})
- `dreamhack` / `ctf`: 챌린지 단일 타겟(host:port/URL) 바인딩 · Jeopardy 단일 플래그
  (DH{}/flag{}/CTF{} 등 `TAG{}` 자동 인식, `--flag-prefix` 로 추가)

> 터미널 출력은 블루/네이비 팔레트의 색상·박스·정렬 UI 로 렌더링됩니다
> (비-TTY·파이프·`NO_COLOR` 환경에서는 색 자동 비활성 → 로그/CI 안전).

> ⚠️ **대상 범위**: 대회/플랫폼이 명시한 권한 확인 대상만. 그 외 자산 사용 금지
> (Scope Guard 가 코드로 강제). 실제 공격 실행은 사용자 Kali 환경에서.

**승인 모드**(기본=스마트): 범위내·검증통과 명령은 자동 실행, 검증실패(파괴명령 포함)는
자동 거부, **범위 밖만 사람 확인**. `--auto`(완전자동)·`--manual`(완전수동)로 조절.
탐지된 CVE/CWE 는 **공식 출처(NVD·GitHub PoC)에서 자동 수집·캐시**(`--no-enrich`/`--offline`).

> **능동적 완전자동 모드**: `assassin 10.129.1.5 --autonomous`(별칭 `--hackathon`) —
> 한 명령으로 최대 자율 풀이. 범위내 자동승인 + 깊은 재진입 스윕(3) + 병렬 열거(4) +
> 변형 학습 + 전 자동준비(리버스쉘·클라우드·권한상승·크래킹)를 묶어 목표(flag/root)까지
> 스스로 추진합니다. 두뇌까지 쓰려면 `--llm hybrid` 추가. **안전 경계는 유지** —
> 범위 밖·파괴명령·실제 익스플로잇은 여전히 게이트(‘건드려선 안 될 권한’만 사람).
> `--manual` 은 autonomous 보다 우선합니다.

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
pip install -e .                         # 에이전트 설치 → 'assassin' 명령 생성
sudo openvpn your-htb.ovpn               # tun0 → 공격자 IP 자동탐지
```

Python 3.10+ (코어는 표준 라이브러리만, 외부 의존성 없음). LLM 사용 시 `pip install anthropic`(Claude) 또는 Ollama.

> 설치 없이 쓰려면 `cd htb-agent` 에서 `PYTHONPATH=src python3 -m htb_agent ...` 로 실행.

## 실행

설치(`pip install -e .`) 후에는 어디서나 `assassin` 명령을 쓸 수 있습니다.
**처음이라면 먼저 `assassin --doctor`** 로 환경(도구·VPN·LLM)을 점검하세요.

```bash
# 승인제 포트스캔+열거 (명령마다 3분할 해설 + 승인)
assassin 10.129.1.5   # (htb-agent 도 동일 — 하위호환 별칭)

# 범위내 자동승인 + 자격증명(→ 초기 침투·플래그 승격) + 라이트업 생성
assassin 10.129.1.5 --auto --cred administrator:Passw0rd --writeup

# 결과 내보내기: 기계판독 JSON + 블루/네이비 HTML 대시보드
assassin 10.129.1.5 --json --html   # <state-dir>/report_<타겟>.{json,html}

# 명령당 옵션 조합 변형(경우의 수) 수 조절 (기본 2, 1=변형끔)
assassin 10.129.1.5 --variants 3

# Dreamhack / CTF 챌린지 (단일 타겟 + flag{} 모드)
assassin web-chall.dreamhack.games:8080 --platform dreamhack
assassin http://ctf.example.com/chall --platform ctf --flag-prefix myctf
assassin chall.dreamhack.io:8080 --platform dreamhack --category pwn --llm hybrid   # 카테고리 힌트로 LLM 유도

# 승인 모드: 완전자동 / 완전수동 / 오프라인(CVE 자동수집 끔)
assassin 10.129.1.5 --auto
assassin 10.129.1.5 --manual
assassin 10.129.1.5 --offline

# LLM 두뇌 / 중단 후 재개 / 설정 파일
assassin 10.129.1.5 --llm hybrid --llm-tier standard   # 하이브리드(Ollama+Claude 라우팅/폴백)
assassin 10.129.1.5 --llm claude --llm-tier standard
assassin 10.129.1.5 --resume
assassin 10.129.1.5 --config config/config.example.json
```

전체 옵션: `assassin --help` (설치 전: `PYTHONPATH=src python3 -m htb_agent --help`).

> **완성형 지식으로 시작**: 59개 주제 전체의 **종합 레퍼런스 번들 시드**(개요·핵심
> 기법/열거·표준 도구/명령·블루팀 탐지·완화·권위 출처)가 저장소에 포함되어, 누구가
> clone 해도 **오프라인에서 동일하게 심화 지식을 가진 완성형 상태로 시작**한다(CI
> 불변식으로 완비·깊이·섹션 강제). 웹 취약점·AD 공격체인·서비스 열거·전술 전반 포괄.
> **일괄 온라인 보강**: `assassin --learn all` — 59개 주제의 최신 본문을 권위
> 출처에서 한 번에 덧씌움(오프라인이면 출처 포인터만, 시작 지식은 번들 시드가 보장).
> **내 자료 학습**: `assassin --ingest ./my-writeups/` — .md/.txt/.pdf 파일/디렉터리를
> 지식베이스 노트로 학습(원문 보존). 본인이 올린 자료는 **참조 허용** — RAG 가 풀이 중 참조(P1 금지는 외부 라이트업 자동수집뿐).
> **자율 지식 획득**: `assassin <target> --learn-gaps` (autonomous 모드 기본 활성) —
> 풀이 중 **모르는 기술/제품을 만나면 스스로 권위 출처에서 찾아 배워** KB 에 즉시
> 반영한다(예: MongoDB 관측 → NoSQLi 지식 자동 연결·학습). 매핑 불가한 용어는
> 지어내지 않고 '미해석 공백'으로 기록(수동 조사 안내). allowlist·P1 유지.
> **인터넷 검색 학습**: `assassin <target> --web-learn` (autonomous 기본 활성) —
> 카탈로그 밖 '미해석 공백'을 **넓은 인터넷 검색**으로 학습해 KB 에 반영한다. 단
> **HTB 라이트업은 출처 불문(공식·제3자) 전부 차단**(HTB 라이트업은 오직 사용자
> 본인 ingest 로만 유입). 일반 기법 아티클·공식 문서는 허용하되 **교차검증**(출처 신뢰등급 A/B 또는 독립 출처 상호확인 + 보안 관련성) 통과분만 채택. 가져온 내용은 노트로만
> 저장(실행 안 함, 신뢰불가 데이터). 오프라인에선 생략.

> **자가학습**(권위 출처만, 라이트업 미참조): `assassin --learn kerberoasting`
> (MITRE ATT&CK·OWASP·PortSwigger·RFC 등 허용 도메인 → 지식베이스 노트로 축적,
> `--learn list` 로 주제 목록). 도구·공격기법·개념/정의·프로토콜을 학습합니다.

> **리버스쉘 페이로드 생성**(실행 안 함): `assassin --revshell 10.10.14.5:4444`
> (bash/nc/python3/php/powershell/socat 등 + 리스너·안정화 힌트).
> **자동 준비**: 풀이 실행 중 공격자 IP(tun0 자동탐지 또는 `--attacker-ip`)가 확보되면
> 초기 침투용 리버스쉘 페이로드를 **별도 명령 없이 자동 생성**해 리포트·라이트업·
> JSON/HTML 에 포함합니다(생성만 — 실제 셸 획득은 권한 확인 대상에서 사용자가 직접,
> 리스너 포트는 `--lport`, 기본 4444).
> **AWS/S3 열거 자동 준비**: 풀이 중 호스트명/도메인이 확보되면 **버킷명 후보 +
> 비인증 점검 명령(aws s3 ls --no-sign-request·curl·s3scanner·cloud_enum·자격증명 확인)을
> 자동 생성**해 리포트·라이트업·JSON/HTML 에 포함합니다(생성만 — AWS 엔드포인트는
> 타겟 범위 밖이라 실행은 사용자가 권한 확인 자산에서 직접). 단독 실행: `assassin --cloud acme.htb`.

> **권한 상승 플레이북 자동 준비**: OS(Linux/Windows/AD) 식별 시 **포스트-익스플로잇
> 권한상승 열거·점검 체크리스트(sudo -l·SUID·capabilities·cron·커널·토큰·서비스
> 오구성·LinPEAS/WinPEAS + 커널/탐지CVE 기반 LPE 후보)를 자동 생성**해 리포트·
> 라이트업·JSON/HTML 에 포함합니다(생성만 — 획득한 대상 셸에서 사용자가 직접 실행).
> 단독 실행: `assassin --privesc linux`.

> **해시 크래킹 자동 준비**: 실행 출력·크리덴셜에서 **해시(Kerberoast/AS-REP/
> NetNTLMv2/유닉스 crypt/NT 등)를 자동 수집·식별해 john·hashcat 명령(올바른
> 모드/포맷·워드리스트)을 자동 생성**합니다(생성만 — 크래킹은 사용자 환경에서 실행).
> 단독 실행: `assassin --crack '$krb5tgs$23$...'`.

> **데모(네트워크·실도구 없이 전체 흐름 보기)**: `python3 scripts/demo.py`
> (라이트업 저장: `python3 scripts/demo.py --write out/`). 실전 운영·트러블슈팅은
> **[docs/OPERATIONS.md](docs/OPERATIONS.md)** 참고.

---

## 핵심 특징

| 분류 | 내용 |
|---|---|
| 안전 | Target-Binding 범위강제 · 명령 검증(문법·base64·해시·포트·파괴명령) · 승인 게이트(스마트/auto/manual) · **능동적 완전자동(`--autonomous`)** · 신뢰불가 출처 인젝션 차단 |
| 관측 | nmap·HTTP(쿠키·보안헤더·로그인폼·CMS)·gobuster/ffuf/feroxbuster/nikto/whatweb·smb·ldap·dns/snmp 파싱 |
| 식별 | Linux vs Windows-AD 증거기반 판정(확신도) · 플랫폼 프로파일(HTB/Dreamhack/CTF) |
| 지능 | 지식베이스(사용자 학습·자가학습으로 성장, 관련도 기반 노트 주입=경량 RAG) · 단계 순서 오케스트레이터 · **월드 모델(구조화 상태 단일 상태원, LLM 컨텍스트 주입)** · **반복·재진입 스윕(유한)** · **단계 게이팅(권한레벨 전제조건)** · 옵션 조합 변형 + **실행결과 기반 변형 학습** · **병렬 열거(I/O)** · LLM(Claude/Ollama/**하이브리드**·플랫폼/카테고리 인식·**분석가 역할**·**JSON 출력 계약**·**적응형 tier 승격**) · **권위출처 자가학습(`--learn`/일괄 `--learn all`)·자료 수집(`--ingest`)** |
| 목표 | CVE/CWE 탐지·매핑 + **자동 수집(NVD)** · user.txt/root.txt·CTF 단일 플래그 · **리버스쉘 생성(`--revshell`) + 자동 준비(공격자 IP 확보 시)** · **AWS/S3 열거 자동 준비(`--cloud`, 호스트명 확보 시 버킷후보+점검 생성)** |
| 공격 | **리버스쉘·AWS/S3·권한상승·해시크래킹 자동 준비(생성 전용)** — 공격자 IP/호스트명/OS/해시 확보 시 페이로드·열거·LPE 체크리스트·john/hashcat 명령 자동 생성(`--revshell`/`--cloud`/`--privesc`/`--crack`) |
| 운영 | 중단/재개 · 크리덴셜 볼트(해시 PtH) · 감사 로그 · 설정 파일 · 도구 설치 스크립트 · **환경 자가진단(`--doctor`)** |
| 산출 | 라이트업 자동 생성(htb-ctf-writeup-v5 / Tistory 13섹션) · **결과 내보내기(JSON·HTML 대시보드)** |

원칙: 승인제 · **외부 라이트업 미참조(사용자 자료·권위 출처만)** · 무한루프 금지 · 증거기반(〔확인〕/〔추정〕).

> 기본 동봉 학습 규칙: `knowledge/rules/htb-startingpoint-tier0.json` — 사용자가 제공한
> HTB Starting Point Tier 0(Meow·Fawn·Dancing·Redeemer·Explosion·Preignition·Mongod·Synced)
> 라이트업에서 학습한 서비스별 비인증/약한자격 점검 규칙(telnet·ftp·smb·redis·mongodb·rsync·rdp·web).
> 학습데이터를 더 넣을수록 제안이 풍부해집니다(성장).
>
> 동봉 **공개 취약점 지식**(특정 머신 라이트업 아님 · 출처 NVD/MITRE/벤더):
> `knowledge/vulns/common-services.json` — 배너/버전 탐지형 원격 서비스 CVE
> (Exim·Webmin·Tomcat Ghostcat·Grafana·Jenkins·Confluence·Spring·Struts·Drupal·PHP-CGI),
> `knowledge/rules/linux-privesc.json` · `windows-privesc.json` — 권한상승·측면이동 방법론
> (SUID/sudo/capabilities·PwnKit·Dirty Pipe/COW·Kerberoast·Zerologon·DCSync·PtH, 전부 승인제·크리덴셜 게이트),
> `knowledge/rules/htb-attack-techniques.json` — 확충 공격기법(웹: JWT·NoSQLi·GraphQL·
> SSRF→IMDS·CORS·요청 스머글링 / AD: ADCS ESC1·제약없는 위임, 출처 PortSwigger/OWASP/MITRE/SpecterOps).

---

## 테스트

```bash
cd htb-agent && python3 tests/run_all.py     # 47 스위트 1092 테스트
```

네트워크·도구 없이도 러너 주입으로 전 로직 검증. CI(GitHub Actions)가 push/PR 마다
**파이썬 3.10~3.13 매트릭스**로 테스트+컴파일(게이트) + ruff/mypy(비차단) 수행.
버전 확인: `assassin --version`.

---

## 한계 (과장 금지)

- 명령 검증은 "형식적 무오류 + 실행 가능 형태"까지 보장(도구별 옵션 의미·해시 정답은 미보장).
- OS/취약점 판정은 증거기반 확신도 — 약하면 `〔추정〕` 표기.
- LLM 비용은 추정치. 실제 공격·VPN 은 Kali 환경 전용.
