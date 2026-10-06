# 학습 시드: ssrf (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn ssrf` 로 갱신.

SSRF 는 서버가 공격자 지정 URL 로 요청하게 만든다. 내부망 스캔·클라우드 메타데이터(169.254.169.254 IMDSv1, GCP metadata.google.internal + Metadata-Flavor 헤더)에서 임시 자격 탈취→클라우드 횡이동. 우회: 리다이렉트·DNS 리바인딩·대체표기. CWE-918. 완화: 아웃바운드 화이트리스트·IMDSv2·메타데이터 차단.

- 출처(검증): https://portswigger.net/web-security/ssrf
