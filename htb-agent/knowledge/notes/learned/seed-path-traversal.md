# 학습 시드: path-traversal (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn path-traversal` 로 갱신.

경로순회(../): 파일경로 입력 조작으로 범위밖 파일 읽기/쓰기(/etc/passwd, web.config). 우회: 인코딩(%2e)·이중인코딩·절대경로·널바이트·접두검증 우회. CWE-22. 블루팀: 요청에 ../·인코딩 변종·민감경로 패턴 탐지. 완화: 정규화후 기준디렉터리 검증·허용목록.

- 출처(검증): https://portswigger.net/web-security/file-path-traversal
