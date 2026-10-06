# 학습 시드: request-smuggling (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn request-smuggling` 로 갱신.

HTTP 요청 밀반입: 프론트/백엔드 길이해석 불일치(CL.TE/TE.CL/TE.TE)로 요청 경계 조작→캐시오염·인증우회·요청탈취. HTTP/2 다운그레이드 변종. 블루팀: 모호한 CL/TE 헤더·비정상 파이프라인 탐지. 완화: 일관된 파서·HTTP/2 end-to-end·모호헤더 거부.

- 출처(검증): https://portswigger.net/web-security/request-smuggling
