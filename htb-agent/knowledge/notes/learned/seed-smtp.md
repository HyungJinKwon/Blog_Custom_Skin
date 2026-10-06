# 학습 시드: smtp (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn smtp` 로 갱신.

RFC 5321. SMTP(25/465/587). 열거: VRFY/EXPN/RCPT TO 로 사용자 유효성 확인, 오픈릴레이 점검. 보안: 스푸핑·릴레이 남용·헤더인젝션. 블루팀: VRFY/EXPN 남용·비정상 릴레이 탐지. 완화: VRFY 비활성·인증 릴레이·SPF/DKIM/DMARC.

- 출처(검증): https://datatracker.ietf.org/doc/html/rfc5321
