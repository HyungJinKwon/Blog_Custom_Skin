# 학습 시드(심화): kerberoasting

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn kerberoasting`. P1: 머신별 라이트업 미참조.

## 개요
Kerberoasting(T1558.003): SPN 보유 서비스계정의 TGS 를 요청해 오프라인 크랙.

## 핵심 기법 · 열거
- 인증된 도메인 사용자면 누구나 TGS 요청 가능
- RC4 TGS → hashcat 13100
- 약한 서비스계정 암호가 핵심 취약

## 표준 도구 · 명령
```
impacket-GetUserSPNs <domain>/user:pass -dc-ip <dc> -request
nxc ldap <dc> -u user -p pass --kerberoasting out.txt
hashcat -m 13100 tgs.txt rockyou.txt
```

## 블루팀 탐지
4769 다수 SPN TGS 요청(단일 계정)·RC4 etype 선호·비정상 서비스티켓 폭증.

## 완화
서비스계정 25자+ 랜덤 암호·gMSA·AES 강제·SPN 최소화·4769 모니터링.

- 출처(검증): https://attack.mitre.org/techniques/T1558/003/

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### CAPEC-509 Kerberoasting
- 출처: https://capec.mitre.org/data/definitions/509.html
- 승격일: 2026-10-07
- 요약: Attack Pattern ID: 509 Abstraction: Detailed Description Through the exploitation of how service accounts leverage Kerberos authentication with Service Principal Names (SPNs), the adversary obtains and subsequently cracks the hashed credentials of a service account target to exploit its privileges. The Kerberos authentication protocol centers around a ticketing system which is used to request/grant access to services and to then access the requested services. As an authenticated user, the advers

### ATT&CK T1558.003 Kerberoasting
- 출처: https://attack.mitre.org/techniques/T1558/003/
- 승격일: 2026-10-07
- 요약: Steal or Forge Kerberos Tickets: Kerberoasting Adversaries may abuse a valid Kerberos ticket-granting ticket (TGT) or sniff network traffic to obtain a ticket-granting service (TGS) ticket that may be vulnerable to Brute Force.[1][2] Service principal names (SPNs) are used to uniquely identify each instance of a Windows service. To enable authentication, Kerberos requires that SPNs be associated with at least one service logon account (an account specifically tasked with running a service[3]).[4
