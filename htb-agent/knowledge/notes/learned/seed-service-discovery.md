# 학습 시드(심화): service-discovery

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn service-discovery`. P1: 머신별 라이트업 미참조.

## 개요
서비스 열거(T1046): 포트별 서비스 심층 열거 — HTB enum 핵심. 서비스별 표준 절차 모음.

## 핵심 기법 · 열거
- FTP(21): 익명·쓰기가능·설정 노출
- SMB(445): 널세션·공유·RID
- SNMP(161/udp): community(public)·snmpwalk
- NFS(2049): showmount·no_root_squash
- Redis(6379): 무인증·keys·웹셸
- rsync(873): 모듈 나열·익명
- LDAP(389): naming context·사용자
- RPC(111): rpcinfo·NFS 연계
- MSSQL(1433)/MySQL(3306): 기본자격·xp_cmdshell

## 표준 도구 · 명령
```
nmap -sC -sV -p- <target>
snmpwalk -v2c -c public <target> ; onesixtyone <target>
showmount -e <target>                          # NFS
redis-cli -h <target> ; rsync -av rsync://<target>/
nxc smb <target> -u '' -p '' --shares
```

## 블루팀 탐지
다수 서비스 동시 프로브·비정상 열거 트래픽·무인증 접근 성공.

## 완화
불필요 서비스 제거·인증 강제·버전 노출 최소화·분할.

- 출처(검증): https://attack.mitre.org/techniques/T1046/

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### ATT&CK T1046 Network Service Discovery
- 출처: https://attack.mitre.org/techniques/T1046/
- 승격일: 2026-10-07
- 요약: Network Service Discovery Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation. Common methods to acquire this information include port, vulnerability, and/or wordlist scans using tools that are brought onto a system.[1] Within cloud environments, adversaries may attempt to discover services running on other cloud hosts. Additionally, if the cloud environment i
