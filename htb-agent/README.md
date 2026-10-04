# ASSASSIN — 승인제 자동 풀이 에이전트 (HTB · Dreamhack · CTF)

```
▄▀█ █▀ █▀ ▄▀█ █▀ █▀ █ █▄░█
█▀█ ▄█ ▄█ █▀█ ▄█ ▄█ █ █░▀█
```

레드팀 학습·모의해킹·CTF 연습용. **권한이 확인된 대상에 한정**해 동작하는,
승인제(Human-in-the-loop) 자동 풀이 보조 에이전트. (패키지명/명령: `assassin`, `htb-agent`)

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
assassin 10.129.1.5   # 또는 htb-agent

# 범위내 자동승인 + 자격증명(→ 초기 침투·플래그 승격) + 라이트업 생성
htb-agent 10.129.1.5 --auto --cred administrator:Passw0rd --writeup

# 결과 내보내기: 기계판독 JSON + 블루/네이비 HTML 대시보드
htb-agent 10.129.1.5 --json --html   # <state-dir>/report_<타겟>.{json,html}

# 명령당 옵션 조합 변형(경우의 수) 수 조절 (기본 2, 1=변형끔)
htb-agent 10.129.1.5 --variants 3

# Dreamhack / CTF 챌린지 (단일 타겟 + flag{} 모드)
assassin web-chall.dreamhack.games:8080 --platform dreamhack
assassin http://ctf.example.com/chall --platform ctf --flag-prefix myctf

# 승인 모드: 완전자동 / 완전수동 / 오프라인(CVE 자동수집 끔)
assassin 10.129.1.5 --auto
assassin 10.129.1.5 --manual
assassin 10.129.1.5 --offline

# LLM 두뇌 / 중단 후 재개 / 설정 파일
htb-agent 10.129.1.5 --llm hybrid --llm-tier standard   # 하이브리드(Ollama+Claude 라우팅/폴백)
htb-agent 10.129.1.5 --llm claude --llm-tier standard
htb-agent 10.129.1.5 --resume
htb-agent 10.129.1.5 --config config/config.example.json
```

전체 옵션: `htb-agent --help` (설치 전: `PYTHONPATH=src python3 -m htb_agent --help`).

> **데모(네트워크·실도구 없이 전체 흐름 보기)**: `python3 scripts/demo.py`
> (라이트업 저장: `python3 scripts/demo.py --write out/`). 실전 운영·트러블슈팅은
> **[docs/OPERATIONS.md](docs/OPERATIONS.md)** 참고.

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

> 기본 동봉 학습 규칙: `knowledge/rules/htb-startingpoint-tier0.json` — 사용자가 제공한
> HTB Starting Point Tier 0(Meow·Fawn·Dancing·Redeemer·Explosion·Preignition·Mongod·Synced)
> 라이트업에서 학습한 서비스별 비인증/약한자격 점검 규칙(telnet·ftp·smb·redis·mongodb·rsync·rdp·web).
> 학습데이터를 더 넣을수록 제안이 풍부해집니다(성장).
>
> 동봉 **공개 취약점 지식**(특정 머신 라이트업 아님 · 출처 NVD/MITRE/벤더):
> `knowledge/vulns/common-services.json` — 배너/버전 탐지형 원격 서비스 CVE
> (Exim·Webmin·Tomcat Ghostcat·Grafana·Jenkins·Confluence·Spring·Struts·Drupal·PHP-CGI),
> `knowledge/rules/linux-privesc.json` · `windows-privesc.json` — 권한상승·측면이동 방법론
> (SUID/sudo/capabilities·PwnKit·Dirty Pipe/COW·Kerberoast·Zerologon·DCSync·PtH, 전부 승인제·크리덴셜 게이트).

---

## 테스트

```bash
cd htb-agent && python3 tests/run_all.py     # 33 스위트 608 테스트
```

네트워크·도구 없이도 러너 주입으로 전 로직 검증. CI(GitHub Actions)가 push/PR 마다
테스트+컴파일(게이트) + ruff/mypy(비차단) 수행.

---

## 한계 (과장 금지)

- 명령 검증은 "형식적 무오류 + 실행 가능 형태"까지 보장(도구별 옵션 의미·해시 정답은 미보장).
- OS/취약점 판정은 증거기반 확신도 — 약하면 `〔추정〕` 표기.
- LLM 비용은 추정치. 실제 공격·VPN 은 Kali 환경 전용.
