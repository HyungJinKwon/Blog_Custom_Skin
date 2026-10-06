# 학습 시드: graphql (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn graphql` 로 갱신.

GraphQL API 공격: 인트로스펙션(__schema)으로 스키마 노출, 과도조회·중첩쿼리 DoS, 배칭으로 레이트리밋/브루트포스 우회, 인가누락 필드 접근. 엔드포인트: /graphql /api. 블루팀: 인트로스펙션 질의·비정상 깊이/배치 탐지. 완화: 프로덕션 인트로스펙션 차단·깊이/복잡도 제한·필드 인가.

- 출처(검증): https://portswigger.net/web-security/graphql
