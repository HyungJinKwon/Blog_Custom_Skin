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
> (Scope Guard 가 코드로 강제 — 가드가 해석하지 못하는 주소 표기는 기본 확인 대상).
> 실제 공격 실행은 사용자 Kali 환경에서.

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
범위 안이라도 **동적·원격 코드 실행**(파이프→셸, `eval`, `IEX`, 명령 치환 등)은 자동실행하지
않고 사람 검토로 넘깁니다(`--auto`/`--autonomous` 에선 수동 제안으로 강등).
단계·라운드·명령 수에 상한이 있어 무한루프가 없습니다. 각 명령은 도구별로
**유효·안전한 옵션 조합 변형(경우의 수)** 을 몇 가지 더 시도해(`--variants`),
한 가지 방식만 보고 포기하지 않습니다 — 변형도 유한하며 3관문을 그대로 통과합니다.

**처음부터 끝까지의 사용법은 [docs/USAGE.md](docs/USAGE.md)** (설치·모드·플랫폼·지식 자동 반영·산출물·트러블슈팅).
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
# (HTML 상단 '한눈에 보기': 3관문 지표·플래그 출처·지식 기반·안전 경계·단계 진행 요약 — 발표/심사용)
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
> **성장 공유(검토 후 승격)**: 학습 노트(`learned-*.md`)는 환경마다 달라 커밋하지 않으므로,
> 그대로 두면 사람마다 성장이 따로 일어난다. `assassin --promote <주제|all>` 은 그중 **품질 관문**
> (권위 출처 · 충분한 요약 · 웹페이지 군더더기 없음 · 라이트업 신호 없음)을 통과한 항목만 번들 시드의
> `## 최신 보강(승격)` 섹션으로 옮긴다(사람이 다듬은 본문은 그대로, 같은 출처는 교체, 주제당 3건 상한).
> 결과 diff 를 커밋·PR → 리뷰·CI(같은 관문 재검사) 통과로 병합되면 **모든 사용자의 시작 지식이 함께 자란다.**
> 카탈로그에서 교체·삭제된 출처의 승격분은 다음 승격 때 자동 정리되고, 내용이 같으면 최초 승격일을 유지한다.
> **자동 반영(손 안 대도 됨)**: ① 공유 — GitHub Actions `KB 자동 승격`(매주 월 03:17 KST, 수동 실행 가능)이
> `--learn all` → `--promote all` → **전체 테스트 검증** 후 PR 을 열고 자동 병합한다(저장소 설정: Actions 쓰기 권한 +
> "Allow GitHub Actions to create and approve pull requests"). ② 로컬 — 타겟을 실행하면 **하루 1회** 공유 저장소의
> 최신 시드를 조회해 로컬과 다른 것만 받고, 같은 품질 검증(필수 섹션·권위 출처·승격 관문·크기·해시)을 통과한 것만
> `knowledge/shared_seeds/`(git 추적 안 함) 캐시에 적용한다. 데이터만 받고 코드는 받지 않으며, 추적 파일을 건드리지
> 않아 git pull 충돌이 없다. 로컬에서 편집 중(미커밋)인 시드는 덮어쓰지 않고, 이후 git pull 로 시드가 바뀌면 캐시본은
> 자동으로 무시된다. 즉시 동기화: `assassin --kb-sync` · 끄기: `--no-kb-sync` / `--offline` / `ASSASSIN_NO_KB_SYNC=1`.
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
> · **발표용 라이브 시연**: `python3 scripts/demo.py --live [--pace 2]` — 범위 밖 바인딩 거부 →
> 정찰·식별 → 열거 → **3관문 작동(검토 강등·범위 밖 미실행·통계)** → 지식(완성형 시작·검증 공유) → 산출의 6단계를 순서대로 보여줌
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
cd htb-agent && python3 tests/run_all.py     # 54 스위트 1429 테스트
```

네트워크·도구 없이도 러너 주입으로 전 로직 검증. CI(GitHub Actions)가 push/PR 마다
**파이썬 3.10~3.13 매트릭스**로 테스트+컴파일(게이트) + ruff/mypy(비차단) 수행.
버전 확인: `assassin --version`.

---

## 한계 (과장 금지)

- 명령 검증은 "형식적 무오류 + 실행 가능 형태"까지 보장(도구별 옵션 의미·해시 정답은 미보장).
- OS/취약점 판정은 증거기반 확신도 — 약하면 `〔추정〕` 표기.
- LLM 비용은 추정치. 실제 공격·VPN 은 Kali 환경 전용.

## 전체 CLI 옵션

<!-- CLI-OPTIONS:START (scripts/gen_cli_docs.py 가 자동 생성 — 직접 수정 금지) -->
| 옵션 | 설명 |
|---|---|
| `--version` | show program's version number and exit |
| `--doctor` | 환경 자가진단(도구·LLM·VPN 점검, 스캔 안 함). 완전 초보자 권장 첫 실행 |
| `--revshell` `LHOST:LPORT` | 리버스쉘 페이로드 생성(실행 안 함). 'IP:PORT' 또는 'PORT'(공격자 IP 자동/--attacker-ip). 권한 확인 대상 전용 |
| `--learn` `TOPIC` | 권위 출처 자가학습(도구·공격기법·개념·프로토콜)을 지식베이스에 저장. 예: --learn kerberoasting / burp / http. 전체 일괄: --learn all. 목록: --learn list |
| `--promote` `TOPIC` | 로컬 학습 노트(learned-&lt;주제&gt;.md) 중 품질 관문을 통과한 항목을 번들 시드의 '최신 보강(승격)' 섹션으로 승격. 결과를 커밋·PR 하면 모든 사용자에게 공유. 예: --promote sqli / 전체: --promote all |
| `--kb-sync` | 공유 저장소의 최신 번들 시드를 지금 동기화(검증 통과분만 로컬 캐시에 적용). 타겟 실행 시에는 하루 1회 자동 |
| `--no-kb-sync` | 실행 시 공유 시드 자동 동기화 끄기(환경변수 ASSASSIN_NO_KB_SYNC=1 도 동일) |
| `--ingest` `PATH` | 사용자 제공 자료(.md/.txt 파일 또는 디렉터리)를 지식베이스 노트로 미리 학습. 예: --ingest ./my-writeups/ |
| `--cloud` `NAME` | AWS/S3 열거 자동 준비(생성 안 실행). 호스트명/도메인에서 버킷명 후보+비인증 점검 생성. 예: --cloud acme.htb. 권한 확인 자산 전용 |
| `--privesc` `OS` | 권한상승 플레이북 자동 준비(생성 안 실행). OS 별 열거·점검·LPE 체크리스트 생성. 예: --privesc linux. 획득한 대상 셸에서 직접 실행 |
| `--crack` `HASH` | 해시 크래킹 자동 준비(생성 안 실행). 해시 종류 식별 + john/hashcat 명령 생성. 예: --crack '$krb5tgs$23$...'. 권한 확인 자산 해시 전용 |
| `--platform` | 플랫폼 프로파일 (기본 htb). dreamhack/ctf=단일 타겟+flag{} 모드 |
| `--category` | Jeopardy 카테고리 힌트(web/pwn/rev/crypto/forensic/misc). CTF/Dreamhack 에서 LLM 제안을 카테고리에 맞게 유도 |
| `--flag-prefix` | 우선 인식할 플래그 접두 (반복 가능, 예: --flag-prefix DH). 플랫폼 기본값에 추가 |
| `--range` | 허용 타겟 CIDR (반복 가능). 생략 시 플랫폼 기본(HTB만 대역 강제) |
| `--attacker-ip` | 공격자 VPN IP (반복 가능). 생략 시 tun0 자동탐지 |
| `--lport` | 리버스쉘 리스너 포트(자동 준비 페이로드용, 기본 4444) |
| `--cred` | 자격증명 'user:pass' / 'user:pass:domain' / 'user:pass:domain:nthash' (반복 가능). Pass-the-Hash 는 'user:&lt;32hex&gt;' 또는 'user::domain:&lt;NT\|LM:NT&gt;'. {user}/{pass}/{domain}/{hash} 제안을 실행 후보로 승격 |
| `--config` | 설정 파일(.json/.yaml). 우선순위: CLI &gt; 설정파일 &gt; 기본값 |
| `--autonomous`, `--hackathon` | 능동적 완전자동 모드: 범위내 자동승인 + 깊은 재진입 스윕 + 병렬 열거 + 변형학습 + 전 자동준비. 목표(flag/root)까지 스스로 추진(안전 게이트 유지) |
| `--auto` | 완전 자동: 범위내+검증통과만 실행, 범위 밖은 조용히 건너뜀(무프롬프트) |
| `--manual` | 완전 수동: 모든 명령을 실행 전 확인(승인제 최대) |
| `--no-enrich` | CVE/CWE 자동 수집(NVD/GitHub) 비활성 |
| `--learn-gaps` | 자율 지식 획득: 풀이 중 모르는 기술을 권위 출처에서 자동 학습해 KB 에 즉시 반영(allowlist·P1 유지). autonomous 모드에선 기본 활성 |
| `--no-learn-gaps` | 자율 지식 획득 비활성(autonomous 모드에서도 끔) |
| `--web-learn` | 인터넷 검색 학습: 카탈로그 밖 '미해석 공백'을 웹 검색으로 학습해 KB 반영. HTB 라이트업(공식·제3자)은 가드로 차단. autonomous 기본 활성 |
| `--no-web-learn` | 인터넷 검색 학습 비활성(autonomous 모드에서도 끔) |
| `--offline` | 오프라인: 네트워크 수집 금지(캐시만 사용) |
| `--enrich-cache` | CVE 캐시 디렉토리 (기본 &lt;knowledge&gt;/cve_cache) |
| `--max-attempts` | 포트스캔 폴백 최대 시도 (기본 4, 무한루프 방지) |
| `--max-enum` | enum 자동실행 최대 개수 (기본 6, 무한확장 방지) |
| `--max-rounds` | ENUM/LLM 반복 라운드 수 (기본 2, 무한루프 방지) |
| `--max-sweeps` | 단계 재진입 스윕 수 (기본 2). 새 관측·크리덴셜로 이전 단계 재시도. 상태 정체 시 조기종료(유한) |
| `--max-parallel` | 열거 명령 동시 실행 수 (기본 1=순차). 독립 명령의 I/O 만 병렬 — 게이트·결과처리는 순차로 안전 |
| `--variants` | 명령당 옵션 조합 변형 수 (기본 2, 1=변형끔). 경우의 수 시도 |
| `--knowledge` | 지식베이스 디렉토리 (기본 ./knowledge). 사용자 규칙/노트로 성장 |
| `--llm` | LLM 두뇌 백엔드 (기본 none=규칙기반). claude=API, ollama=로컬, hybrid=둘을 단계 난이도로 라우팅+폴백(장점극대·단점보완) |
| `--llm-tier` | LLM 티어 (비용/성능) |
| `--state-dir` | 세션 상태 저장 디렉토리 (기본 ./state) |
| `--resume` | 저장된 상태에서 재개 (RECON 재사용, 재스캔 생략) |
| `--no-save` | 상태 저장 안 함 |
| `--log-file` | 감사 로그(JSONL) 경로. 생략 시 &lt;state-dir&gt;/audit_&lt;타겟&gt;.jsonl |
| `--no-audit` | 감사 로그 비활성 |
| `--writeup` | 풀이 라이트업 Markdown 생성(경로 생략 시 writeup_&lt;타겟&gt;.md) |
| `--writeup-format` | 라이트업 형식: htb(기본, htb-ctf-writeup-v5) / tistory(13섹션) |
| `--json` | 결과를 기계판독 JSON 으로 내보내기(경로 생략 시 &lt;state-dir&gt;/report_&lt;타겟&gt;.json) |
| `--html` | 결과를 HTML 대시보드로 내보내기(블루/네이비, 경로 생략 시 &lt;state-dir&gt;/report_&lt;타겟&gt;.html) |
<!-- CLI-OPTIONS:END -->
