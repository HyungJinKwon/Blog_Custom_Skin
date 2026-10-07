# 학습 시드(심화): dcsync

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn dcsync`. P1: 머신별 라이트업 미참조.

## 개요
DCSync(T1003.006): 복제권한으로 DC 에서 자격(해시) 원격 추출.

## 핵심 기법 · 열거
- Replicating Directory Changes 권한 필요(DA/특정 ACL)
- krbtgt·전 사용자 해시 덤프 → Golden Ticket 연계

## 표준 도구 · 명령
```
impacket-secretsdump <domain>/user:pass@<dc>
impacket-secretsdump -just-dc-user krbtgt <domain>/user:pass@<dc>
mimikatz: lsadump::dcsync /user:krbtgt
```

## 블루팀 탐지
4662 복제권한 사용(DS-Replication-Get-Changes)·비정상 복제 요청元(비DC).

## 완화
복제권한 최소화·Tier0 분리·4662 감사·krbtgt 보호.

- 출처(검증): https://attack.mitre.org/techniques/T1003/006/

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### ATT&CK T1003.006 DCSync
- 출처: https://attack.mitre.org/techniques/T1003/006/
- 승격일: 2026-10-07
- 요약: OS Credential Dumping: DCSync Adversaries may attempt to access credentials and other sensitive information by abusing a Windows Domain Controller's application programming interface (API)[1] [2] [3] [4] to simulate the replication process from a remote domain controller using a technique called DCSync. Members of the Administrators, Domain Admins, and Enterprise Admin groups or computer accounts on the domain controller are able to run DCSync to pull password data[5] from Active Directory, whic
