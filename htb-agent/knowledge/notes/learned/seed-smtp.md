# 학습 시드(심화): smtp

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn smtp`. P1: 머신별 라이트업 미참조.

## 개요
SMTP(25/587): 메일 전송. 사용자 열거·오픈릴레이.

## 핵심 기법 · 열거
- VRFY/EXPN/RCPT TO 로 사용자 유효성 확인
- 오픈릴레이·헤더 인젝션·스푸핑

## 표준 도구 · 명령
```
smtp-user-enum -M VRFY -U users.txt -t <target>
nc <target> 25   # VRFY root / RCPT TO:
```

## 블루팀 탐지
VRFY/EXPN 남용·비정상 릴레이·대량 RCPT.

## 완화
VRFY/EXPN 비활성·인증 릴레이·SPF/DKIM/DMARC.

- 출처(검증): https://datatracker.ietf.org/doc/html/rfc5321

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### RFC 5321 SMTP
- 출처: https://datatracker.ietf.org/doc/html/rfc5321
- 승격일: 2026-10-07
- 요약: This document is a specification of the basic protocol for Internet electronic mail transport. It consolidates, updates, and clarifies several previous documents, making all or parts of most of them obsolete. It covers the SMTP extension mechanisms and best practices for the contemporary Internet, but does not provide details about particular extensions. Although SMTP was designed as a mail transport and delivery protocol, this specification also contains information that is important to its use
