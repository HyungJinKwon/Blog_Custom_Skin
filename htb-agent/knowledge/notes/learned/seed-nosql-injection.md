# 학습 시드: nosql-injection (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn nosql-injection` 로 갱신.

NoSQL 주입(MongoDB 등): 쿼리 연산자 주입. 인증우회 {"$ne":null}/{"$gt":""}, JSON 연산자·$where JS 실행. 구문(연산자)·블라인드(불리언/시간) 유형. 블루팀: 입력에 $연산자·JS 포함 요청 탐지. 완화: 입력 타입검증·연산자 금지·ODM 파라미터화.

- 출처(검증): https://portswigger.net/web-security/nosql-injection
