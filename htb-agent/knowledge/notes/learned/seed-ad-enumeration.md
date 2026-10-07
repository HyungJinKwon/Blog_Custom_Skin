# 학습 시드(심화): ad-enumeration

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn ad-enumeration`. P1: 머신별 라이트업 미참조.

## 개요
AD 열거(T1087): 도메인 사용자·그룹·ACL·신뢰·공격경로 수집. BloodHound 핵심.

## 핵심 기법 · 열거
- BloodHound/SharpHound 로 그래프 수집→최단 권한경로
- ldapsearch·nxc 로 사용자/그룹/정책 열거
- ACL 남용(GenericAll/WriteDacl)·세션 수집

## 표준 도구 · 명령
```
nxc ldap <dc> -u user -p pass --bloodhound --collection All --dns-server <dc>
bloodhound-python -u user -p pass -d <domain> -ns <dc> -c All
ldapsearch -x -H ldap://<dc> -b 'dc=d,dc=local' '(objectClass=user)'
```

## 블루팀 탐지
LDAP 대량 조회·SAMR/LSARPC 열거·비정상 세션 수집 활동.

## 완화
LDAP 조회 모니터링·최소권한·ACL 정리·티어링.

- 출처(검증): https://attack.mitre.org/techniques/T1087/002/

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### ATT&CK T1087.002 Domain Account Discovery
- 출처: https://attack.mitre.org/techniques/T1087/002/
- 승격일: 2026-10-07
- 요약: Account Discovery: Domain Account Adversaries may attempt to get a listing of domain accounts. This information can help adversaries determine which domain accounts exist to aid in follow-on behavior such as targeting specific accounts which possess particular privileges. Commands such as net user /domain and net group /domain of the Net utility, dscacheutil -q group on macOS, and ldapsearch on Linux can list domain users and groups. PowerShell cmdlets including Get-ADUser and Get-ADGroupMember
