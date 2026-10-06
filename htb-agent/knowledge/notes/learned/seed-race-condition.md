# 학습 시드: race-condition (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn race-condition` 로 갱신.

경쟁조건(TOCTOU): 동시요청으로 검사-사용 간극 악용 — 한도우회(쿠폰·출금 중복), 제한우회. 단일패킷/last-byte 동기화로 공략. 블루팀: 동일리소스 초단시간 다중요청 탐지. 완화: 원자적 연산·잠금·멱등성·DB 제약.

- 출처(검증): https://portswigger.net/web-security/race-conditions
