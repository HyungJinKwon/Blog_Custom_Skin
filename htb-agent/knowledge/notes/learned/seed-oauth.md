# 학습 시드: oauth (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn oauth` 로 갱신.

OAuth 2.0 결함: redirect_uri 검증부실(토큰 탈취), state 누락(CSRF), 암시적흐름 토큰노출, 코드 재사용·탈취. 계정탈취로 이어짐. 완화: redirect_uri 정확일치·state/PKCE·1회성 코드·짧은 만료. 블루팀: 비정상 redirect·코드 재사용 탐지.

- 출처(검증): https://portswigger.net/web-security/oauth
