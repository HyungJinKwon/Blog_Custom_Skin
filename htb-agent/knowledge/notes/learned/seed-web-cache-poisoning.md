# 학습 시드: web-cache-poisoning (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn web-cache-poisoning` 로 갱신.

웹캐시 오염: 캐시키 미포함 입력(언키드 헤더/파라미터)으로 악성응답을 캐시에 저장→타 사용자에 서빙. XSS·리다이렉트 전파. 블루팀: 캐시키 불일치·비정상 헤더 반영 탐지. 완화: 키 정규화·언키드 입력 제거·Vary 정확설정.

- 출처(검증): https://portswigger.net/web-security/web-cache-poisoning
