# 학습 시드: sqli (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn sqli` 로 갱신.

사용자 입력이 SQL 쿼리에 미검증 삽입→인증우회·데이터유출·RCE. 유형: in-band(UNION/error), blind(boolean/time). 도구 sqlmap. 완화: 파라미터화 쿼리(prepared statement), 최소권한 DB계정.

- 출처(검증): https://owasp.org/www-community/attacks/SQL_Injection
