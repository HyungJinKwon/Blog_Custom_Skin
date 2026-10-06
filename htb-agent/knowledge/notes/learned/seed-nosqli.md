# 학습 시드: nosqli (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn nosqli` 로 갱신.

NoSQL 인젝션(MongoDB 등)은 질의 연산자를 주입한다. JSON 바디에 {"$ne":null}/{"$gt":""}/{"$regex":".*"} 를 넣어 인증 우회·데이터 추출, 쿼리스트링은 param[$ne]=x 형태. $where/맵리듀스로 JS 실행 가능 경우도. CWE-943. 완화: 입력 타입 강제·연산자 금지·스키마 검증.

- 출처(검증): https://owasp.org/www-community/Injection_Flaws
