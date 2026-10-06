# 학습 시드: clickjacking (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn clickjacking` 로 갱신.

UI 리드레싱: 투명 iframe 로 피해자 클릭을 공격자 의도 액션에 탈취. 프레임 삽입 가능 시 성립. 완화: X-Frame-Options: DENY/SAMEORIGIN, CSP frame-ancestors 'self'. 블루팀: 민감 액션 페이지의 프레임 허용 헤더 부재 점검.

- 출처(검증): https://portswigger.net/web-security/clickjacking
