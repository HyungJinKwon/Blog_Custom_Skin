# 학습 시드(심화): silver-ticket

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn silver-ticket`. P1: 머신별 라이트업 미참조.

## 개요
Silver Ticket(T1558.002): 서비스계정 해시로 특정 서비스 TGS 위조.

## 핵심 기법 · 열거
- 서비스계정/머신계정 해시로 해당 서비스만 접근
- DC 로그 미발생(은밀)

## 표준 도구 · 명령
```
impacket-ticketer -nthash <svc-hash> -domain-sid <sid> -spn <spn> user
```

## 블루팀 탐지
DC 미경유라 탐지 난이도↑. 서비스 측 비정상 티켓·호스트 불일치.

## 완화
머신계정 암호 정기 롤링·AES·서비스 측 PAC 검증.

- 출처(검증): https://attack.mitre.org/techniques/T1558/002/

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### ATT&CK T1558.002 Silver Ticket
- 출처: https://attack.mitre.org/techniques/T1558/002/
- 승격일: 2026-10-07
- 요약: Steal or Forge Kerberos Tickets: Silver Ticket Adversaries who have the password hash of a target service account (e.g. SharePoint, MSSQL) may forge Kerberos ticket granting service (TGS) tickets, also known as silver tickets. Kerberos TGS tickets are also known as service tickets.[1] Silver tickets are more limited in scope in than golden tickets in that they only enable adversaries to access a particular resource (e.g. MSSQL) and the system that hosts the resource; however, unlike golden ticke
