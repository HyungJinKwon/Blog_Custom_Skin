# 학습 시드: jwt (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn jwt` 로 갱신.

JWT 공격은 서명 검증 약점을 노린다: (1) alg:none 으로 서명 제거, (2) HS256↔RS256 혼동(공개키를 HMAC 키로), (3) kid 파라미터 경로주입/SQLi, (4) 약한 HS256 시크릿 오프라인 크랙(hashcat -m 16500, jwt_tool). 위조 토큰으로 권한 상승/인증 우회. 완화: 강한 키·alg 화이트리스트·kid 검증.

- 출처(검증): https://portswigger.net/web-security/jwt
