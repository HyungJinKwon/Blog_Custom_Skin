# 변경 이력

형식: 추가(Added) · 변경(Changed) · 수정(Fixed) · 안전(Safety). 버전은 [SemVer](https://semver.org/lang/ko/)를 따릅니다.

## [2.6.9] — 2026-10-09

실전(connected.htb) 피드백 — PoC 후보가 터미널에 안 보이고, 요약된 출력에서 파싱이 어긋나던
문제를 고치고, 1순위 PoC 자동 선택(⭐)을 추가. 실행 경계(생성 전용)는 그대로.

### 수정(Fixed)
- **searchsploit 파싱이 요약(collapsed) 출력에서 어긋남**: `finding.output` 은 요약기가 줄바꿈을
  공백으로 합치는데, 기존 라인 기반 파서가 전체를 1개 항목으로 오인했다. 토큰 기반(정규식)으로
  바꿔 '제목 | locator(경로/URL)' 을 항목별로 정확히 분리(헤더 'Path'·구분선 자동 제외, `-w` URL
  지원). collapsed·raw 둘 다 견고.
- **PoC 후보가 터미널에 안 보임**: 공개 익스 후보가 '기타 안내'로 분류돼 6개 컷오프에 밀려
  숨겨졌다. 전용 묶음 **`🎯 익스플로잇 후보 — PoC 고르기`** 로 맨 위에, 전부 표시(자율 풀이의
  핵심 결정이라 자르지 않음).

### 추가(Added)
- **1순위 PoC 자동 선택(⭐)**: 버전 접두 매칭으로 추려진 후보 중 1순위를 ⭐로 자동 선택하고,
  받아 검토할 명령(`searchsploit -m <edb-id>`)까지 제시. 실제 실행은 사람이 `--exploit-exec
  --poc` 로(생성 전용 경계 유지 — 자동 선택까지, 자동 실행은 옵트인 수동 트리거).
- **테스트**: `test_exploit_view.py`(전용 묶음·전부 표시 회귀 가드) + `test_searchsploit.py`
  collapsed/URL 파싱 가드 + `test_exploit_lookup.py` ⭐·fetch 검증.

## [2.6.8] — 2026-10-09

### 추가(Added)
- **searchsploit 결과 파싱 + 대상 버전 매칭**(`searchsploit.py`): 레지스트리가 자동 실행한
  `searchsploit <product>` 출력을 파싱해(제목·exploit-db locator·제목 내 버전), 핑거프린트된
  `world.web_version` 과 **접두 호환 매칭**으로 '대상 버전에 맞는 PoC'를 앞세워 상위 N개로
  추린다. access 단계 수동 제안에 `# <product> PoC 후보(버전 … 대조)` 로 표시 → 사람/LLM 이
  고를 선택지를 좁혀 준다. 버전 미상이면 상위 후보를 그대로 제시(대조는 사람이).
  · **안전 경계**: 파싱·추림만 — PoC 실행·다운로드·선택을 하지 않는다(생성 전용 유지).
- **테스트**: `test_searchsploit.py`(파서·버전 매칭 11건) + `test_exploit_lookup.py` 통합(후보 추림).

## [2.6.7] — 2026-10-09

### 추가(Added)
- **Exploit 레지스트리 제품별 공략 안내(`note`)**: 레지스트리를 `ExploitEntry(lookup, note)` 로
  확장해, 각 제품(FreePBX·Elastix·WordPress·Joomla·Drupal·Tomcat·Jenkins·Grafana·GitLab·
  Gitea·phpMyAdmin·Nextcloud·osTicket)에 '어디를(패널·경로) 어떤 취약 유형으로 볼지'의 일반
  가이드를 달았다. access 단계의 공개 익스 후보 수동 제안에 이 note 가 함께 표시된다
  (예: FreePBX → admin 패널·recordings/ajax·버전 대조·약한 관리자 자격). `note_for()` 추가.
  · **안전 경계**: note 는 '공략 각도' 설명일 뿐 PoC·익스·실행 명령이 아니다. lookup 은 여전히
    searchsploit 조회만(생성 전용·RCE 표면 금지 유지).

## [2.6.6] — 2026-10-09

### 추가(Added)
- **Exploit 레지스트리(3단계 기반, `exploits.py`)**: 핑거프린트된 웹앱 제품키
  (`world.web_product`, 2.6.4)에 맞는 **공개 익스 '조회' 명령**(searchsploit)을 access 단계에서
  게이트로 올린다(제품당 1회·멱등). 지원: FreePBX·Elastix·WordPress·Joomla·Drupal·Tomcat·
  Jenkins·Grafana·GitLab·Gitea·phpMyAdmin·Nextcloud·osTicket. 조회 결과(버전별 공개 익스
  목록)는 enum_findings 에 남아 다음 분석·명령 생성에 되먹여지고, 특정된 PoC 는 **대상 버전
  대조 후 사람/LLM 이 골라 3관문으로 실행**한다.
  · **안전 경계**: 레지스트리에는 searchsploit **조회 명령만** 담긴다 — 실제 익스 실행 명령·
    PoC 코드·원격 RCE 는 하드코딩하지 않는다(생성 전용 경계·RCE 표면 금지 유지).
- **테스트**: `test_exploit_lookup.py`(레지스트리 데이터·게이트 경유 조회·캡처·멱등, 10건).

## [2.6.5] — 2026-10-09

실제 머신 실행 중 드러난 LLM 신뢰성 문제(하이브리드 두뇌가 400 에러·거절로 사실상
멈춤)와 발판 단계 점검을 다룬다. 안전 경계(생성 전용·3관문)는 그대로.

### 수정(Fixed)
- **LLM 오류 원인 가시화**: HybridRouter 가 백엔드 오류를 80자로 잘라 보관해, API
  400(invalid_request_error)의 **핵심 message 가 가려져 진단 불가**였다. 이제 `_err_text`
  가 anthropic `body.error.message` 를 우선 뽑아 넉넉히(300자) 보관하고, **차단되기 전에도**
  라우팅 요약에 `최근오류: …` 로 1건 노출한다(간헐 400 추적용).
- **빈 content 요청 가드**(ClaudeProvider): 빈 사용자/시스템 프롬프트는 Anthropic API 가
  400 으로 거부한다 — 상태 변화 없는 라운드 등에서 빈 프롬프트가 넘어가면 요청 자체가 실패하므로,
  빈 user 는 최소 지시로 대체하고 빈 system 블록은 생략한다.

### 변경(Changed)
- **exploit-exec 발판 단계(2단계 읽기 되먹임)**: 발판에서 읽은 privesc 열거·플래그 출력을
  스테이지 종료 후 `_run_vuln` 으로 재스캔해 새 크리덴셜·CVE·플래그를 월드/분석에 반영한다
  (다음 분석이 'GTFOBins 다음 수'를 제안하도록). 열거 되먹임만 — 자동 익스 실행이 아니다.
  목표 달성 시 자격 루프를 즉시 빠져나오도록 정리(return→break).

### 추가(Added)
- **테스트**: `test_exploit_exec_stage.py`(1단계 점검 — 스킵 조건·게이트 경유 실행·플래그
  캡처·provenance·sshpass 래핑, 10건), `test_llm_errdiag.py`(오류 진단 노출 회귀 가드, 6건).

## [2.6.4] — 2026-10-09

실제 머신(FreePBX 박스) 실행 피드백 반영 — 열거가 리드를 충분히 파기 전에 멈추지 않도록
자율 enum 예산을 올리고, 관측된 웹앱 제품/버전을 식별해 공개 익스 조회를 자동 구체화한다.

### 추가(Added)
- **웹앱 핑거프린트 → `{product}`/`{version}` 자동 치환**(`vuln.fingerprint_webapp`,
  `WorldModel.set_web_app`, `Orchestrator._fill_fingerprint`): 관측 코퍼스(제목·generator·
  Server/X-Powered-By 헤더·enum 출력)에서 알려진 웹앱(FreePBX·WordPress·Joomla·Drupal·
  Tomcat·Jenkins·Grafana·GitLab·Gitea·phpMyAdmin·Nextcloud·osTicket·Elastix)의 제품키·
  버전을 식별해 월드에 기록한다. KB 제안의 `searchsploit {product} {version}` 같은
  placeholder 가 '관측된 실제 값'(`searchsploit freepbx 15.0.16.75`, 버전 미상이면
  `searchsploit freepbx`)으로 치환돼 **수동 제안이 아닌 자동 실행 후보**가 된다. 미식별이면
  placeholder 를 그대로 둬(섣부른 치환 금지) 기존처럼 수동 제안으로 남긴다. 웹앱 미식별 시
  nmap `-sV` 서비스 제품으로 폴백. 외부 조회 없이 관측 텍스트만 매칭(P1 유지).

### 변경(Changed)
- **자율(`--autonomous`) enum 예산 상향**: `--max-enum` 자율 기본값 10 → **24**. 실제 머신에선
  10개로는 유효 후속 명령이 큐에 남은 채 조기 종료됐다(연결된 리드를 덜 팜). 2.6.2 의 반복
  억제 + 명령 중복제거 + 상태 정체 조기종료가 상한을 안전하게 유지하므로 폭을 넓혔다
  (명시 `--max-enum`/설정값이 있으면 그대로 우선).

## [2.6.3] — 2026-10-09

### 추가(Added)
- **발판 자동 실행(`--exploit-exec`, 옵트인·기본 OFF)**: 확보한 **평문 자격**(열거 또는
  `--cred user:pass`)으로 SSH 발판을 잡아 `user.txt`/`root.txt` 를 자동으로 읽고, 권한상승
  **열거**(`id`·`sudo -l`·SUID·capabilities — 파괴 없음)까지 기존 3관문(검증·범위·승인)을 거쳐
  실행한다. 해시·빈 자격은 건너뛰고, 22번 닫힘·`sshpass` 미설치면 조용히 스킵(감사 로그에 사유).
  침입(익스플로잇) 자체는 아직 자동화하지 않으며(자격이 이미 있는 Easy 머신용), 플래그 확보 시
  🏁 SOLVED 패널에 값·출처(공략 유래=검증)를 표시. OFF 일 때 동작은 이전과 100% 동일.

### 문서(Docs)
- **README·docs/USAGE 최신화**: `--exploit-exec`(§10.2)·🏁 SOLVED 결과화면(§4)·vhost 자동
  이름해석·VM 기본 실행환경 설정(§12)을 반영하고, 전체 CLI 옵션 표를 재생성.

## [2.6.2] — 2026-10-09

### 변경(Changed)
- **LLM 폐루프 집중도 — 반복 억제**: 같은 '종류'(repetition.signature: 바이너리+플래그)
  시도가 이미 3회 이상 '실패'했으면 그 종류의 새 명령을 실행하지 않고 건너뛴다(수동 제안으로
  보관). 기존엔 경고만 했던 산발 반복(예: `curl -s ×8`)을 예산·시간 관점에서 끊어 "다음
  한 수"에 집중. 성공/유의미 출력이 있던 종류는 세지 않음(_gate/_repetition_saturated).

### 추가(Added)
- **FakeFoothold 테스트 하네스**(`tests/test_foothold_harness.py`): exploit-exec 실행
  엔진을 실 타겟 없이 검증하는 복붙용 템플릿. 발판→플래그 캡처→provenance(공략 유래)→
  SOLVED 루프를 결정적으로 테스트. user/root 분리 명령 분류 회귀 가드 포함.

## [2.6.1] — 2026-10-09

### 추가(Added)
- **머신형 자율 풀이 KB 경로**(`knowledge/rules/machine-autosolve.json`, 5규칙): 서비스
  버전→공개 익스 자동 식별(searchsploit), 확인 CVE→공개 PoC 매핑, FreePBX 관리패널
  식별(버전·익스·기본자격), SSH 평문자격 발판→user/root 플래그 읽기(분리 명령으로 kind
  정확 분류), SSH 발판→권한상승 자동 열거. 자율 실행 루프가 '다음 익스/발판/플래그' 를
  규칙으로 인지하게 해 산발적 시도를 줄인다. 모두 suggest(생성) — 실행은 게이트 통과.

## [2.6.0] — 2026-10-09

완전 자동 흐름의 마찰 제거 — vhost 이름해석 자동화, VM 을 기본 실행환경으로 지정 가능,
목표 달성 시 플래그 값 결과화면(🏁 SOLVED). 안전장치(스코프·검증·3관문)는 그대로.

### 추가(Added)
- **🏁 "다 풀었다(SOLVED)" 결과화면**: 목표 달성 시 저장된 user.txt/root.txt(single 은
  플래그) **값**을 결과 맨 끝에 표시(+출처 검증 요약). `--resume` 후에도 유지.
- **vhost 이름해석 자동 등록**: 리다이렉트(`→ http://connected.htb/`)에서 발견한
  호스트명을 **타겟 IP 로 스코프 해석맵에 자동 등록** → 이후 그 vhost 명령이 범위 안으로
  인식돼 프롬프트·스킵이 사라진다. OS 이름해석(`/etc/hosts`)은 쓰기 권한이 있으면 자동
  추가, 없으면 '조용한 반복 실패' 대신 **한 번만 실행할 명령을 1회 안내**. 스코프는 타겟
  IP 로만 묶으므로 범위를 넓히지 않는다.
- **VM 을 기본 실행환경으로**: 설정파일에 `sandbox: "vm"` 과 `vm_ssh`(및 `vm_ssh_key`·
  `vm_ssh_port`·`vm_sudo`·`vm_confine`)를 저장하면 `assassin <IP>` 만으로 그 VM(VMware
  등)에서 실행된다. docker 외 VM 경로를 CLI 플래그 없이 기본화.

### 변경(Changed)
- 첫 실행 안내에 **완전 자동(무프롬프트) = `--autonomous`** 와 격리 실행(docker/vm)을
  또렷하게 안내(초보자 혼동 감소). `--vm-ssh-port` 기본값을 설정 우선(None)으로.

## [2.5.1] — 2026-10-09

최종 마무리 검수(차원별 심층 검수)에서 재현 확인한 결함 수정 + 파괴적 명령 차단 확대.

### 수정(Fixed)
- **자율학습 상태 오염(lateral 전제)**: `_acquire_knowledge` 가 학습 토픽을 `world.loot`
  에 적재해, 자격증명·발판이 없어도 lateral 단계 전제가 충족돼 투기적 LLM 라운드를
  소모하고 성장 지표를 왜곡하던 문제 수정. 학습 지식을 `world.learned` 로 분리.
- **`--resume` 시 provenance 판정 손실**: 재개 시 flag 출처(verdict)를 재계산해
  `looked-up`(라이트업·학습 유래 의심)이 `exploit-derived` 로 승격되거나, 오프라인 공략
  플래그가 `local-derived` 로 강등되던 문제 수정. 첫 실행의 판정을 상태에 보존·복원.
- **정찰 중 Ctrl+C**: 첫 포트스캔 도중 중단 시 raw 트레이스백 + 상태 유실로 `--resume`
  약속이 깨지던 문제 수정. 정찰을 중단 처리로 감싸 상태 저장 후 정상 종료하고, 최상위
  진입점에 Ctrl+C·예외 가드 추가(전체 추적은 `ASSASSIN_DEBUG=1`).

### 안전(Safety)
- **파괴적 명령 차단 확대**: `shred`·`wipefs`·`mkfs`족(`mke2fs`/`mkswap`/`mkfs.*`)·
  `find … -delete|-exec rm`·루트/홈 `chmod`·`chown -R`·디바이스/시스템경로 `dd`·`truncate`·
  리다이렉트 절단(`> /etc/…`)을 토큰 단위로 차단(auto 모드 자동실행 fail-open 해소).
  디바이스 매칭을 loop/dm-/md/sr/disk-by-id/mapper 로 확대. 상대·작업공간 경로는 오탐 없이 통과.

### 추가(Added)
- **`--max-llm`**: LLM 제안 명령 최대 개수 플래그(기본 5, 자율모드 8) — 기존 config 필드를
  CLI 로 노출하고 자율 램프에 포함(다른 한계값과 대칭).

### 변경(Changed)
- 소스 배포(sdist)에 `knowledge/`·`bench/`·문서 포함(`MANIFEST.in`). wheel 은 KB 를 포함하지
  않는다는 제약을 pyproject 주석에 명확화(소스 트리·`pip install -e .`·`--knowledge` 사용).

## [2.5.0] — 2026-10-09

### 추가
- **`--dry-run` 계획 미리보기**: 정찰·분석은 수행하되 제안된 enum/LLM/파일 명령은 **실행하지 않고
  보여만** 준다(게이트까지 통과 → `dry-run: 제안만(미실행)` 비고). 자율 실행 전 무해 점검용.
- **무인 진행 heartbeat**: 스윕마다 1줄 요약(스윕 N/M·경과·enum/LLM 수·플래그·비용) 출력 —
  장시간 완전자율 실행의 폭주 감시·발표 시연 가시성. 비대화형(`quiet`)에선 억제.
- **오타 옵션 제안**: 알 수 없는 CLI 옵션에 `difflib`로 가장 가까운 실제 옵션을 제안
  (예: `--prt` → "혹시 `--lport`?"). 거리가 먼 오타엔 제안하지 않음. `argparse` 기본 오류를 보강.
- **틈새 기법 일반 규칙**(`knowledge/rules/niche-techniques.json`): AD CS 취약 템플릿 탐색(certipy
  ESC)·NoSQL 인젝션·JWT 약점(alg none/키 혼동) — 서비스 키 기반 정석 규칙. 모두 관측 타겟 한정.
- **패킷 분석·웹 프록시 도구 사용성**: 샌드박스에 `tcpdump` 추가(헤드리스 CLI). Wireshark·Burp Suite 는
  GUI 라 자율 실행 대상이 아니며, 자동화 등가물(`tshark`·`tcpdump`·`mitmproxy`·`zaproxy`)로 커버됨을
  `docs/USAGE.md §10.1`에 정리(모든 도구는 레지스트리 등록·`--doctor`/`--install-missing` 연동).
- **성장 공유(G1)** — `--export-stats`/`--import-stats`: 실행 학습 통계(변형 성공률)를 파일로
  주고받아 사용자 간 성장을 compounding. 통계는 `binary+fragment→succ/att` 뿐이라 명령 전체·타겟·
  출력이 담기지 않아 공유해도 안전. `VariantStats.merge()`로 succ/att 합산.
- **역량 등급(G2)** — `--doctor`에 `full/standard/baseline` 등급 + '한 단계 올리는 법' 표시.
  환경별 성능 편차(LLM 백엔드·도구·샌드박스)를 가시화(안전·범위 강제는 모든 등급 동일).
- **통합 최신화(G3)** — `--update`: 공유 시드 동기화 + 권위출처 재학습·승격을 한 명령으로
  (`--offline`이면 네트워크 생략). CVE/CWE 는 실행 시 자동 수집·캐시.
- **KB 버전 태깅(G4)** — `knowledge.KB_VERSION` 신설, `--doctor` 푸터에 표시(동기화 호환·진단 가시화).
- **서비스 열거 일반 규칙 신설**(`knowledge/rules/service-enum.json`): NFS(showmount/마운트)·
  SNMP(snmpwalk/onesixtyone)·WordPress(wpscan) — 머신 비의존 정석 기법 규칙. 업로드 라이트업群의
  **역량 공백 분석**(다루는 서비스·기법 발자국 ↔ 우리 KB/툴 커버리지 대조)으로 식별한 공백만 보강.
  라이트업의 머신별 정답/플래그는 무결성 가드(provenance)상 적재하지 않음 — '정답 암기'가 아니라
  '일반 역량' 강화.
- **샌드박스 툴 커버리지 확대**(`sandbox/Dockerfile`·`scripts/install_tools.sh`): evil-winrm·
  bloodhound.py·wpscan·hydra·telnet·ftp·nfs-common(showmount)·onesixtyone 추가 — 라이트업群이 자주
  쓰는 범용 도구(Windows 셸·AD 경로분석·CMS 열거·NFS/SNMP 열거)의 미설치 공백 해소.
- **네이티브 tool use(구조화 명령 제안)**: Claude 백엔드에서 `propose_commands` 도구를 강제 호출해
  명령 후보를 스키마대로 JSON 으로 받는다(텍스트 파싱 취약성 제거). tool_calls 가 있으면 우선 사용,
  없으면 기존 텍스트 파싱으로 폴백 — Ollama·구버전 프로바이더 호환.
- **플래그 출처 강화(CTF-Abacus 2608.26237)**: `looked-up`(값이 웹학습·자가학습 노트에 그대로
  있었음 — 라이트업·검색 의심) · `reasoning-only`(값이 명령 입력에 있음 — 지어냈을 수 있음) 판정 추가.
  '검증된 풀이율'은 `genuine`(exploit-derived)만 집계. `KnowledgeBase.external_notes()` 추가.
- **Results Verifier(AutoPentester 2510.05605)**: 범위 밖으로 거부될 명령만, 타겟 자리표시자·사설
  (RFC1918)/타겟대역 IP 오타를 바인딩 타겟으로 자동 교정해 복구(공격자 IP·공인/문서 IP 보존).
  교정본도 3관문을 다시 통과. 끄려면 `fix_commands=False`. (`command_fixer.py`)
- **연구 근거 문서** `docs/RESEARCH.md`: 5개 논문(AutoPentester·MazeRunner·CTF-Abacus·HackWorld·
  Anomaly-Agent)의 핵심 기여 ↔ 이 저장소 기능 대응표 + 재구현 시 지킨 안전 경계.
- **열거 서비스별 라운드로빈**: KB 제안을 서비스(태그)별 버킷으로 모아 round-robin 으로 예산 분배 —
  한 서비스가 예산을 독식하지 않고 각 서비스가 먼저 한 번씩 돌 기회를 갖는다(탐색 폭 확대).
- **`--install-missing [카테고리]`**: 빠진 보안 도구를 저장소 공식 `install_tools.sh` 로 자동 설치
  (빠진 도구가 있는 카테고리만 전달). `--doctor` 안내도 이 명령으로 갱신.
- **`--cred-file <경로>`**: 자격증명을 파일에서 일괄 로드(`CredentialVault.load_file`). 인라인 `--cred`
  와 함께 쓸 수 있고, 둘 다 범위·검증 경계를 그대로 거친다.
- **`--list-sessions`**: 저장된 세션(타겟) 목록을 출력(`StateStore.list_targets`) — `--resume` 대상 확인용.
- **실제 Kali 라이브 검증 가이드** `docs/VALIDATION.md` · **문서 일관성 검사**
  (`tests/test_docs_consistency.py`): `assassin` 예시에 쓰인 `--옵션`이 실제 CLI 에 있는지 검사.

### 변경
- **anthropic SDK 플로어 상향**: `anthropic>=0.40` → `anthropic>=1.0`(현행 메이저 1.x 반영;
  `messages.create`·시스템 캐시 블록·tool use 사용은 1.x 호환). requirements 주석도 동반 갱신.
- **OWASP 카탈로그 URL 정규화**: `owasp.org/www-community/*` → `community.owasp.org/*`(OWASP 가
  308 영구 이전). 사전학습 카탈로그 8건 + 승격된 시드 노트 8건 동시 갱신 → 리다이렉트 1홉 절약,
  카탈로그↔시드 정합. `.owasp.org` 하위도메인이라 allowlist 그대로 통과.
- **가격표 출처 스탬프 갱신**(2026-09 → 2026-10; 요율 값은 이미 현행).
- **분석가 티어 적응화**: `analyze()`가 항상 STRONG(opus)을 쓰던 것을, 추론 난이도가 높은 국면
  (첫 분석=가설 기록 없음 · 막힌 가설 존재 · 직전 확신도 '하')에만 STRONG, 평상시 갱신은
  STANDARD(sonnet)로 라우팅 → 분석 비용 절감(난이도-티어 정합). 하이브리드는 여전히 Claude 우선.
- **LLM 라운드 병렬 실행**: `_llm_round`가 제안 명령을 순차 실행하던 것을, 파일 없는 일반 프로브는
  enum 과 동일하게 병렬 배치(게이트 순차→I/O 동시→처리·태깅 순차·결정적), 파일 액션(익스플로잇·
  솔버 스크립트)은 다단계 안전을 위해 순차 유지. 실벽시계 단축.
- **프롬프트 캐싱 적중 개선**: `suggest` 시스템 프롬프트에 호출마다 바뀌는 잔여 예산(max_items)을
  박아 ephemeral 캐시가 매번 미스되던 문제 수정 — 시스템 프롬프트를 고정 상한으로 만들고 라운드별
  실제 상한은 비캐시 영역(사용자 프롬프트·도구 스키마·파싱 절단)으로 전달 → 큰 시스템 블록 재청구 방지.
- **논리적 흐름 — 막힌 국면 투기 억제**: 가설 원장이 있는데 쫓을 대상이 없고(focus 없음) 모든 열린
  가설이 '막힘'이면 같은 상태에서 투기적 LLM 제안 라운드를 건너뛴다(KB 열거는 유지, 다음 스윕서
  상태 성장 시 재개) → 낭비 LLM 호출 절감 + 전이 판단 명시(`llm_round_skipped` 감사 이벤트).
- **사전학습 수집 타임아웃 상향(6초 → 10초)**: `learn.py` fetcher·`ReferenceLearner` 기본 타임아웃을
  상향해 `--learn all` 배치 중 콜드캐시 대용량 페이지(예: OWASP www-community 42KB+)가 전환적으로
  누락되던 문제를 줄인다. allowlist·라이트업 가드·오프라인 폴백은 불변.
- **로컬(Ollama) 기본 모델 현행화**: 티어 기본값을 `llama3.1:8b/70b` → `qwen2.5:7b`(cheap/standard)·
  `llama3.3:70b`(strong)로 교체. 도구 사용·지시이행이 개선된 세대로 정렬하고 setup 추천표·doctor 안내·
  문서도 동반 갱신. 설치돼 있지 않으면 기존대로 설치된 모델로 자동 대체(`model_for`)하고 `OLLAMA_MODEL`
  로 덮어쓸 수 있어 기존 사용자 영향 없음.
- **CHEAP 티어 모델 현행화**: Claude 백엔드 CHEAP 티어를 `claude-haiku-4-5`(구세대, $1/$5) →
  `claude-haiku-5-5`(현행, ≤100K 프롬프트 $0.10/$0.50·컨텍스트 1M)로 교체. CHEAP 은 호출이 가장
  잦은 enum 단계에 매핑되므로 열거 단계 Claude 비용이 크게 감소하고 지시이행 품질도 개선.
  `pricing.py` 에 `claude-haiku-5-5` 요율 추가(미등록 시 비용 0 집계 → 상한 판정 무력화되던 문제 예방).
- **분석가 콜드스타트 방향성**: 가설 기록이 없는 '첫 분석'에서 백지로 시작하지 않고, 관측된 열린
  서비스·포트마다 표준 공격면을 H1~H3 로 먼저 세우도록 분석가 프롬프트에 지침 추가(노출·정보량 큰
  서비스를 H1 로). 호출 시 방향을 갖고 출발 — 이후 호출은 기존대로 가설 원장을 이어서 갱신.
- 화면 잡음 축소(초보자): 리버스쉘 자동 준비는 대표 3종만 표시하고 전체는 `--json`/`--html` 로.

### 수정
- `knowledge/rules/example.json` 규칙에 `phase` 명시 — KB 전 규칙의 phase 결측 0 보장.
- **설정 파일 `sandbox: vm` 거부되던 문제**: `config.SANDBOX_KINDS` 에 `vm` 누락으로, CLI·구현은
  지원하는데 설정 파일로는 거부됐다 — `vm` 추가로 CLI·설정 경로 일치.
- **설정 파일 `time_budget`/`max_cost` 소수 거부되던 문제**: 두 키가 정수 검증(`_INT_KEYS`)에 묶여
  CLI(`type=float`)·dataclass(`float`)와 어긋났다 — 숫자(정수·소수) 검증으로 분리.

### 정리
- **`main()` 갓-함수 분해(591줄 → 65줄)**: CLI 진입부를 얇게 — 단독 명령 디스패치는
  `_dispatch_standalone`, 타겟 실행 경로는 `_run_target` 로 분리(동작 불변). 가독성·기여 용이성↑.
- **핫패스 메서드 분리**: `_llm_round` 의 컨텍스트 조립을 `_suggest_context` 로, `_gate` 의 타겟
  자동교정을 `_apply_command_fix` 로 추출(로직 밀도 완화, 동작 불변).
- **마라톤 세션 메모리 상한**: `finding.output` 1건당 하드 실링(`_MAX_FINDING_OUTPUT`)을 둬
  '보관 출력 총량 = 시도 수(예산 제한) × 상한' 으로 명시적 bound(유일하게 미제한이던 성장 지점 차단).
- **Provider 예외 계약 문서화**: `LLMProvider.complete`/`ClaudeProvider.complete` 가 API 오류를
  예외로 전파함을 명시(HybridRouter 폴백·서킷브레이커·오케스트레이터 라운드 격리가 의존). 직접
  호출자는 try/except 필요 — 삼키지 않음으로써 하이브리드 복원력 보존.
- 핫패스 private 헬퍼(`_tool_ok`·`_run_vuln`) 의도 docstring 보강.
- 미사용·중복 코드 제거: `ScopeGuard.detect_attacker_ips`(= `environment.detect_vpn_ips` 중복 사본),
  `observation.compressor.summarize_nmap_host`·`render_observation`·`recommend_followup`,
  `command_validator.validate_hex`, `ui.color_enabled`(getter). HTTP fetcher 중복
  (`enrich`·`learn`)은 공용 헬퍼(`util.http_get_text`)로 통합. `Enricher.cwe_url` 은 리포트/라이트업의
  CWE 참조에 연결.

## [2.4.1] — 2026-10-08

### 추가
- **VM 실행 샌드박스 `--sandbox vm`**: 에이전트가 명령을 실행하는 환경을 Docker 외에 **SSH 로 접속한
  가상머신/공격호스트**에서도 돌릴 수 있다(`--vm-ssh user@host` [`--vm-ssh-key`·`--vm-ssh-port`]).
  파이프·스크립트·실도구를 VM 에서 실행하고, 작업공간 파일은 scp 로 올린다. `--vm-confine`(+`--vm-sudo`)
  이면 접속 직후 VM 에 egress 방화벽(타겟 대역만)을 적용·검증해 docker 처럼 완전자율 동적 실행까지
  자동 허용(그 VM 네트워크를 타겟으로 제한하므로 전용 풀이 VM 에서만). 없으면 contained=False 로
  동적 실행은 수동 제안. `--doctor` 에 '실행 샌드박스' 점검 추가(none/docker/vm 고르는 법 안내).

### 추가
- **라이브 벤치 공개세트 확장 + VM/외부 타겟**: 공개 CTF 세트(picoCTF·Dreamhack·HTB Starting
  Point)에서 흔한 기법류를 **원본으로 재구성**해 문제를 늘렸다(복사 아님). loopback 추가 —
  `web-cookie-admin`(권한 쿠키 우회)·`web-lfi-flag`(경로 순회/LFI)·`net-banner-flag`(nc 배너
  상호작용). docker 추가 — `smb-anon-share`·`mysql-empty-root`·`snmp-public`(실서비스).
  그리고 **`kind: "vm"`** — 컨테이너가 아닌 실제 머신(HTB·Dreamhack 머신, VirtualBox/VMware/
  libvirt VM)을 타겟으로. 주소는 `challenge.json` 의 `address` 또는 환경변수 `ASSASSIN_VM_<이름>`
  으로 지정(머신마다 IP 가 달라 파일 수정 없이 덮어쓰기), 선택적 `start_cmd`/`stop_cmd` 로
  부팅/정리(우리가 부팅한 경우에만 종료). `bench/live/vm-htb-example/`(템플릿·README).
- **지식베이스 경로 cwd 독립**: 기본값이 '실행한 폴더의 ./knowledge' 였던 것을, 없으면 패키지에
  번들된 `knowledge/` 로 자동 해석(어느 디렉터리에서 실행해도·설치본에서도 동작). `pyproject.toml`
  에 `package-data` 추가(일반 설치 시 번들 데이터 포함).

### 수정
- 포트스캔 폴백 서비스 추정에서 1337 을 `unknown` 으로(CTF pwn 규칙 매칭) — nc 상호작용 유도.
- `tests/run_all.py`: 스위트당 제한시간(`ASSASSIN_TEST_SUITE_TIMEOUT`, 기본 300초) + 각 스위트
  stdin=/dev/null(대화형 input() 블록 방지) — 네트워크 대기·stdin 상속으로 멈추던 문제 해소.
- 설치 스모크 CI 잡: 새 가상환경 설치 후 소스 밖(다른 cwd)에서 `assassin --doctor`·`--bench`·
  별칭 동작 확인(지식경로 cwd 독립·엔트리포인트 검증).
- 테스트 네트워크 차단: `ASSASSIN_NO_NET=1`(run_all 기본)이면 기본 fetcher(enrich·kb_sync·learn·
  web_search)가 실제 요청을 보내지 않는다(주입 fake fetcher 는 영향 없음) — CI 안정성.

## [2.4.0] — 2026-10-08

완전자율(--autonomous)에서 **실제 익스플로잇까지 자동 수행**할 수 있도록 실행 계층을 넓혔습니다.
기존에는 명령을 한 줄씩(셸 비경유)만 실행해 파이프·스크립트·대화형 세션·첨부파일 분석이 불가능했고,
리버스쉘·권한상승·크래킹은 '생성만' 했습니다. 안전 경계(범위 밖·파괴명령 차단)는 그대로 유지합니다.

### 추가

- **라이브 벤치마크 `--live-bench [DIR]`**: 가짜 응답(오프라인 `--bench`)이 아니라 **실제 취약
  서비스를 띄우고 진짜 도구로 풀어** 성공률·pass@k·검증된 풀이율·시간을 측정한다(발표/심사용
  신뢰 수치). 타겟 종류 두 가지 — `loopback`(파이썬 서비스를 전용 127.0.0.x·표준 포트에 기동,
  nmap 없이 소켓 폴백으로 발견·curl 등 실도구로 풀이) / `docker`(challenge 의 Dockerfile 로
  컨테이너를 전용 IP·표준 포트에 기동, FTP/Redis 등 실서비스; 데몬 없으면 명확히 알리고 건너뜀).
  번들 문제 `bench/live/`(web-robots-hidden·web-header-leak·web-source-comment·ftp-anon·redis-key).
  집계·표·JSON·시도별 감사 로그(`--replay`)는 `--bench` 와 같은 구조 재사용.
- **포트스캔 폴백(nmap 미설치 대응)**: nmap 이 없을 때 순수 파이썬 TCP-connect 스캔으로 열린
  포트를 찾아 정찰이 진행되게 한다(바인딩된 타겟만 스캔 — 범위 밖 불가). 흔한 포트 서비스 추정 +
  짧은 배너. nmap 이 있으면 항상 nmap 사용. (`tools/portscan_fallback.py`, `ReconExecutor` 통합)
- **샌드박스 실행기 `--sandbox {none,shell,docker}`**: `docker` 는 Kali 컨테이너 안에서 `bash -c` 로
  실행(파이프·리다이렉트 가능)하고, 컨테이너 egress 를 **타겟 대역(/32)만 허용**하도록 iptables 로
  강제합니다(기본 DROP). 명령은 비root `agent` + no-new-privileges 로 돌아 정책을 바꿀 수 없습니다
  (`sandbox/Dockerfile`, `scripts/build_sandbox.sh`). `shell` 은 로컬 bash(네트워크 미강제).
- **작업공간 + 첨부파일 `--files PATH`**: 챌린지 소스·바이너리·덤프를 작업공간 `files/` 로 가져오고
  (zip·tar 는 zip-slip 방어로 안전하게 해제), LLM 이 소스를 읽고 취약 지점을 찾습니다. 열린 포트가
  없어도(rev/crypto/forensic) 파일 분석으로 진행합니다.
- **LLM 스크립트 작성·실행**: LLM 이 JSON 응답에 `file:{path,content}` 를 넣으면 익스플로잇·디코더·
  솔버 스크립트를 작업공간에 쓰고 실행합니다. 네트워크가 실행 계층에서 강제되는(docker) 때만 자동
  실행하고, 그 외에는 수동 제안으로 남깁니다. 작성 파일은 감사 로그에 해시·본문과 함께 남습니다.
- **완전자율 승인**: egress 강제 샌드박스에서는 동적·원격 코드 실행(파이프→셸 등)도 자동 승인합니다
  (`auto_approve_contained`) — 정적 검사로 내용을 알 수 없어도 네트워크가 타겟으로 묶여 있기 때문.

### 안전

- **셸 연산자 게이트**: 셸 비경유 실행기에서 파이프·리다이렉트(`|`, `>`, `&&`, `;`)가 인자로 넘어가
  조용히 오작동하던 문제를 실행 전에 거부합니다(따옴표 밖 연산자만 판별, `shell_operators()`).
- **표준입력 차단**: 모든 실행기가 stdin 을 닫아 `nc` 등 입력 대기 도구가 터미널을 가로채거나
  타임아웃까지 멈추지 않습니다.
- **플래그 출처 보정**: 에이전트가 작성한 스크립트 본문이나 명령 문자열 자체에 들어 있는 플래그는
  '로컬 유래(사람 확인)'로 강등해, LLM 이 지어낸 값이 '공략 유래'로 집계되지 않게 합니다.

## [2.3.0] — 2026-10-08

초보자가 처음 실행할 때 막히는 지점과 긴 출력을 정리했습니다.

### 변경

- **인자 없이 실행**: 긴 옵션 목록 대신 시작 3단계(`--doctor` → `--setup-llm` → `assassin <IP>`)를 보여 줍니다.
- **도움말 `--help`**: 옵션을 그룹(시작하기 / 대상·플랫폼 / 실행 방식 / LLM / 시간·한도 / 결과물 / 지식·학습 / 단독 도구)으로 묶고, 짧은 사용법·예시·한국어 문구, 읽기 쉬운 자리표시(`USER:PASS`, `CIDR`, `IP`)로 바꿨습니다.
- **타겟 거부 힌트**: 호스트명이면 `--platform ctf` 명령을, 범위 밖 IP 면 권한 안내와 HTB Target IP 안내를 보여 줍니다(범위 판단은 그대로이고, 대상 IP 를 넣은 우회 명령은 만들지 않습니다).
- **nmap 미설치**: 정찰을 4번 헛돌린 뒤 '호스트 응답 없음'으로 끝나던 것을, 시작 전에 설치 명령과 함께 바로 알려 줍니다. 정찰이 한 번도 실행되지 못하면 '도구/실행 환경 문제(대상 문제 아님)'로 표시합니다.
- **수동 제안**: 묶음마다 앞의 6개만 보여 주고, 같은 꼬리표와 옵션만 덧붙인 변형은 숨깁니다(전체는 `--html`/`--json`).
- **다음 선택지**: 같은 문구가 반복되던 항목을 종류별 한 줄(못 돌린 명령 N개 → `--resume`, 자격증명 필요 → `--cred`)로 묶었습니다.
- **한눈에 보기**: 출력 맨 끝에 결과·서비스·찾은 것·실행 현황·다음에 할 일(최대 3개)을 한 박스로 보여 줍니다.
- **화면 잡음**: 의도적으로 보존한 참고 규칙의 지식베이스 경고를 매 실행 화면에서 숨기고, 내 PC 의 AWS 자격증명 확인 명령을 웹 서비스마다 제안하지 않게 했습니다(`aws` 서비스에서만).
- **박스 정렬**: 여러 줄 안내가 들어가도 박스가 깨지지 않습니다.

## [2.2.0] — 2026-10-08

초보자도 Claude·로컬 LLM(Ollama)을 명령 하나로 연결할 수 있습니다.

### 추가

- **LLM 연결 마법사 `--setup-llm`**: 질문에 답하면 연결부터 확인·저장까지 끝납니다.
  - 백엔드 선택(하이브리드 권장 / Claude만 / 로컬만).
  - Claude: `anthropic` 패키지 확인(설치는 동의 시) → API 키 입력(화면 비표시) → 실제 1회 호출 → 성공한 키만 저장.
  - 로컬: Ollama 설치·서버 확인 → 받아 둔 모델 표시 → PC 메모리에 맞는 모델 추천 → `ollama pull`(동의 시) → 실제 1회 호출.
  - 기본 설정(`~/.config/assassin/config.json`)에 백엔드·로컬 모델·비용 상한(기본 $2)을 저장합니다.
- **`--llm-test`**: 환경 진단에 짧은 실제 호출을 더해 틀린 키·없는 모델·막힌 네트워크를 미리 잡습니다.
- **키 보관**: `~/.config/assassin/credentials`(폴더 700·파일 600, 원자적 쓰기). 실행 시 환경변수로 올리고, 이미 환경변수가 있으면 그쪽이 우선합니다.
- **설정 키**: `llm.ollama_model`, `llm.ollama_host`(환경변수 `OLLAMA_MODEL`·`OLLAMA_HOST`가 우선).

### 변경

- `--config`가 없으면 마법사가 저장한 기본 설정을 자동으로 읽습니다(우선순위 CLI > 환경변수 > 설정 파일 > 기본값, 한 번만 끄기는 `--llm none`).
- `--doctor`가 Claude 키를 가린 값과 출처(환경변수/키 파일)로 보여 주고, 미연결 항목에 `assassin --setup-llm` 안내를 붙입니다.
- LLM 사용 불가 메시지에 마법사 안내를 붙였습니다.

### 안전

- 키는 화면에 가린 값(`sk-ant-…abcd`)만 보이고, 상태 파일·감사 로그·리포트·라이트업에 남지 않습니다(실행 산출물 전수 검사 테스트).
- 패키지 설치·모델 다운로드는 항상 먼저 묻습니다(엔터=아니오). Ollama 설치 스크립트(파이프→셸)는 자동 실행하지 않고 명령만 안내합니다.
- 실제 호출 테스트는 "OK 한 단어로 답하라" 수준의 짧은 요청입니다(공격 명령 아님).

## [2.1.0] — 2026-10-08

하이브리드 LLM이 매번 처음부터 다시 생각하지 않고, 세운 가설을 따라 방향을 유지하며 진행합니다.

### 추가

- **가설 기록(계획 원장, `hypotheses.py`)**: 분석가가 세운 가설 H1~H4의 상태(대기/검증중/확인/기각)·확인 방법·기대 신호·시도한 명령·근거를 들고 갑니다.
  - 분석가 재호출은 **갱신 모드**입니다. 이전 기록과 막힌 가설을 넘기고, 같은 ID는 유지한 채 상태만 바꾸게 합니다.
  - 상태 파일에 저장되어 `--resume` 후에도 계획이 이어집니다.
- **지금 할 일 1개**: 명령 생성(hybrid면 로컬 우선)에는 분석 전문 대신 가설 하나와 확인 방법·기대 신호·이미 해 본 명령만 줍니다.
- **기대 신호 대조**: 결과를 기대 신호와 규칙으로 비교해(LLM 없이) 가설 상태를 갱신하고, 비고에 `H1 신호 일치〔추정〕`/`불일치`를 남깁니다.
- **막힘 → 재계획**: 같은 가설이 2회 연속 어긋나면 `막힘`으로 표시하고 분석가에게 재계획을 요청합니다.
- **가설 보드**: 결과 요약(PLAN)·HTML 대시보드·라이트업에 표시하고, 실행 재생에 계획 갱신·가설 대조·막힘 단계를 보여 줍니다.
- **벤치 LLM 호출 수**: `--bench`에 시도당·풀이 1건당 LLM 호출 수를 추가했습니다.

### 변경

- **재분석 조건**: 명령이 하나 더 실행된 것만으로는 분석가를 다시 부르지 않습니다. 새 크리덴셜·서비스·수집물·취약점·권한·플래그, 가설 확인·기각·막힘 때만 다시 부릅니다. 분석가가 가설을 주지 못하면 예전 방식(결과가 늘 때마다 재판단)으로 돌아갑니다.
- **리포트 JSON 스키마 1.6**: `plan`(가설 기록)을 추가했습니다(하위 호환).

### 안전 (바뀌지 않음)

- 가설 상태는 명령 제안의 방향에만 쓰입니다. 모든 명령은 그대로 검증 → 범위 → 승인 3관문을 거치고, 플래그 출처·목표 달성은 실행 결과로만 판정합니다.
- LLM이 준 가설 문구·기대 신호는 신뢰하지 않는 데이터로 다룹니다(길이 제한, HTML 이스케이프).

## [2.0.0] — 2026-10-08

첫 정식 릴리스. 해커톤·레드팀 교육 용도에 맞춰 시간·비용 관리, 성능 측정, 재생, 초보자 화면을 갖췄습니다.

### 추가

- **시간·비용 상한**
  - `--time-budget 분`: 제한 시간이 지나면 새 명령을 멈추고 산출물을 정리합니다.
  - `--max-cost USD`: LLM 누적 추정 비용이 넘으면 LLM 호출을 멈추고 규칙 기반으로 계속합니다.
- **성능 측정 `--bench`**: 오프라인 모의 문제 12개(easy 6 · medium 5 · hard 1)로 성공률을 측정합니다.
  - 검증된 풀이율(대상과 상호작용해서 얻은 플래그만 인정)과 승인 부담을 함께 보고합니다.
  - 결과는 `results.json`과 문제별 실행 기록으로 남깁니다.
- **실행 재생 `--replay`**: 감사 로그(JSONL)를 단계별로 넘겨 보는 HTML로 만듭니다.
  - 내용은 `textContent`로만 렌더링합니다(XSS 방지).
- **실패 피드백**: 막힌 이유(blockers)를 다음 LLM 라운드 문맥으로 넘깁니다.
- **반복 경고**: 앞서 실패한 것과 같은 종류의 명령이면 승인 전에 `⟳` 경고를 띄웁니다. 경고만 할 뿐 실행을 막지는 않습니다.
- **사실 출처 표시**: 크리덴셜·취약점·수집물마다 어디서 알게 됐는지(도구·버전 매칭 등)를 기록합니다.
- **사람 관찰 입력 `--observe`**: 건너뛴 명령 대신 사람이 직접 확인한 내용(브라우저 화면 등)을 기록합니다.
  - 기록에는 `사람 관찰` 표시가 붙어 에이전트가 검증한 결과와 구분됩니다.
- **다관점 분석가**: 레드팀·개발자·인프라·방어 관점에서 가설 H1–H4를 세우고 계획을 만듭니다.
- **HTTP 요약 단서**: 본문의 주석, 내부 링크, 평문 경로를 최대 5개까지 요약에 남깁니다.
- **승인 화면**: 명령마다 `목적` 한 줄을 보여 줍니다. 검토가 필요한 명령에는 더 안전한 2단계 `대안`을 함께 제시합니다.
- **발표·입문 자료**: `scripts/showcase.sh`(데모 → 벤치 → 재생 HTML → 대시보드를 한 번에)와 1쪽 분량의 [docs/QUICKSTART.md](docs/QUICKSTART.md)를 추가했습니다.
  - 라이브 데모를 7단계로 확장했습니다(승인 목적·대안, 성능 측정 단계 추가).
- **라이선스**: MIT.

### 변경

- **목표 도달 시 종료**: exploit 단계에서 얻은 플래그로만 목표 도달을 판정합니다.
- **재개·중단**: `--resume`이 실행한 명령·결과·플래그를 복원합니다. Ctrl+C로 멈추면 상태를 저장하고 종료 코드 130으로 끝납니다.
- **하이브리드 라우터**
  - 연속 오류가 난 백엔드는 차단(circuit breaker)하고, LLM 거부 응답도 따로 집계합니다.
  - 라우팅·비용 요약을 보고서에 넣습니다.
  - Ollama 모델이 없으면 설치된 모델로 자동 대체합니다.
- **리포트 JSON 스키마 1.5**: `goal_reached`, `llm_routing`, `timed_out`, `elapsed_sec`, `cost_capped`를 추가했습니다(하위 호환).
- **코드 품질**: ruff·mypy 경고를 0건으로 정리했습니다. CI에서 두 검사를 차단 게이트로 바꾸고 버전을 고정했습니다.
- **문서**: 문서에 박혀 있던 테스트 개수를 지우고, 실행할 때 요약이 나오도록 바꿨습니다.

### 안전 (바뀌지 않음)

- 모든 명령은 **검증 → 범위 → 승인** 3관문을 통과해야 실행됩니다. LLM은 검증기·범위·출처 판정을 덮어쓸 수 없습니다.
- 리버스쉘·권한상승·크래킹·클라우드 도구는 **명령 생성까지만** 합니다. 실행은 사람이 결정합니다.
- 승인받지 않은 셸을 계속 열어 두지 않습니다.
- `scope_guard.py`는 타입 주석만 손봤고, 범위 테스트로 동작이 그대로인 것을 확인했습니다.
- BoxPwnr(AGPL-3.0)에서는 아이디어만 참고했고 코드는 가져오지 않았습니다(클린룸 재구현).
