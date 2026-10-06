# 학습 시드: persistence (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn persistence` 로 갱신.

ATT&CK TA0003. 지속성: 재부팅·로그아웃 후 접근유지 — 스케줄작업/크론, 서비스, 레지스트리 Run키, 시작프로그램, SSH authorized_keys, WMI 구독, 웹셸, 계정생성. 블루팀: 자동실행 변경·신규 서비스(7045)·스케줄작업(4698)·authorized_keys 변경 탐지. 완화: 기준선 모니터링·무결성 검사.

- 출처(검증): https://attack.mitre.org/tactics/TA0003/
