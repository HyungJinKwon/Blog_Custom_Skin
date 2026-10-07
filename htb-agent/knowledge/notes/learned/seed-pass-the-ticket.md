# 학습 시드(심화): pass-the-ticket

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn pass-the-ticket`. P1: 머신별 라이트업 미참조.

## 개요
Pass-the-Ticket(T1550.003): 탈취/위조 Kerberos 티켓으로 인증.

## 핵심 기법 · 열거
- ccache/kirbi 티켓 재사용
- Overpass-the-Hash(해시→TGT)

## 표준 도구 · 명령
```
export KRB5CCNAME=<ticket>.ccache; klist
impacket-getTGT <domain>/user -hashes :<nthash>   # OPtH
impacket-psexec -k -no-pass <host>
```

## 블루팀 탐지
비정상 티켓 재사용·호스트 불일치 티켓·4769 이상.

## 완화
티켓 수명 단축·보호된 사용자·tgt 재발급 제한·LSASS 보호.

- 출처(검증): https://attack.mitre.org/techniques/T1550/003/

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### CAPEC-645 Use of Captured Tickets
- 출처: https://capec.mitre.org/data/definitions/645.html
- 승격일: 2026-10-07
- 요약: Attack Pattern ID: 645 Abstraction: Detailed Description An adversary uses stolen Kerberos tickets to access systems/resources that leverage the Kerberos authentication protocol. The Kerberos authentication protocol centers around a ticketing system which is used to request/grant access to services and to then access the requested services. An adversary can obtain any one of these tickets (e.g. Service Ticket, Ticket Granting Ticket, Silver Ticket, or Golden Ticket) to authenticate to a system/r

### ATT&CK T1550.003 Pass the Ticket
- 출처: https://attack.mitre.org/techniques/T1550/003/
- 승격일: 2026-10-07
- 요약: Use Alternate Authentication Material: Pass the Ticket Adversaries may "pass the ticket" using stolen Kerberos tickets to move laterally within an environment, bypassing normal system access controls. Pass the ticket (PtT) is a method of authenticating to a system using Kerberos tickets without having access to an account's password. Kerberos authentication can be used as the first step to lateral movement to a remote system. When preforming PtT, valid Kerberos tickets for Valid Accounts are cap
