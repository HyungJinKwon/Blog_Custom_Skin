# 학습 시드(심화): privilege-escalation

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn privilege-escalation`. P1: 머신별 라이트업 미참조.

## 개요
권한상승(TA0004) 개요: 로컬 enum→오구성/취약점 악용으로 상위권한. 상세는 linux/windows-privesc.

## 핵심 기법 · 열거
- 리눅스: SUID/sudo/cron/capabilities/커널/PATH/쓰기가능 서비스
- 윈도우: 서비스 오구성·토큰·AlwaysInstallElevated·언쿼티드 경로·자격
- 자동 enum→후보 식별→검증

## 표준 도구 · 명령
```
# 리눅스: linpeas.sh ; sudo -l ; find / -perm -4000 2>/dev/null
# 윈도우: winPEAS.exe ; whoami /priv ; seatbelt
```

## 블루팀 탐지
비정상 권한승격·SUID 실행·토큰조작·서비스 바이너리 교체.

## 완화
최소권한·패치·오구성 점검·정기 enum·CIS 벤치마크.

- 출처(검증): https://attack.mitre.org/tactics/TA0004/

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### CAPEC-233 Privilege Escalation
- 출처: https://capec.mitre.org/data/definitions/233.html
- 승격일: 2026-10-07
- 요약: Attack Pattern ID: 233 Abstraction: Meta Description An adversary exploits a weakness enabling them to elevate their privilege and perform an action that they are not supposed to be authorized to perform. Relationships This table shows the other attack patterns and high level categories that are related to this attack pattern. These relationships are defined as ChildOf and ParentOf, and give insight to similar items that may exist at higher and lower levels of abstraction. In addition, relations

### ATT&CK TA0004 Privilege Escalation
- 출처: https://attack.mitre.org/tactics/TA0004/
- 승격일: 2026-10-07
- 요약: Privilege Escalation The adversary is trying to gain higher-level permissions. Privilege Escalation consists of techniques that adversaries use to gain higher-level permissions on a system or network. Adversaries can often enter and explore a network with unprivileged access but require elevated permissions to follow through on their objectives. Common approaches are to take advantage of system weaknesses, misconfigurations, and vulnerabilities. Examples of elevated access include: SYSTEM/root l
