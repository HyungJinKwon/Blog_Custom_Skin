# 학습 시드: ssti (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn ssti` 로 갱신.

서버측 템플릿 주입: 입력이 템플릿 엔진에 평가되어 RCE(Jinja2·Twig·FreeMarker·Velocity). 탐지: {{7*7}}→49 등 폴리글랏. 엔진식별 후 샌드박스 탈출→명령실행. CWE-1336. 블루팀: 템플릿 구문 포함 입력·비정상 자식프로세스 탐지. 완화: 로직리스 템플릿·사용자입력 템플릿화 금지·샌드박스.

- 출처(검증): https://portswigger.net/web-security/server-side-template-injection
