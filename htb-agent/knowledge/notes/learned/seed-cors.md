# 학습 시드: cors (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn cors` 로 갱신.

CORS 설정 오류: Access-Control-Allow-Origin 을 요청 Origin 반사 + Allow-Credentials:true 면 임의 출처가 인증된 응답 탈취. null 출처·와일드카드 서브도메인 신뢰도 위험. 완화: 출처 화이트리스트 엄격검증·credentials 와 와일드카드 병용 금지.

- 출처(검증): https://portswigger.net/web-security/cors
