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
