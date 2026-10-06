# 학습 시드: file-upload (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn file-upload` 로 갱신.

파일 업로드 취약: 검증부실로 웹셸(.php/.jsp/.aspx) 업로드→RCE. 우회: 확장자 이중(.php.jpg)·대소문자·널바이트·Content-Type 위조·매직바이트. 경로제어 시 .htaccess 악용. 블루팀: 업로드 디렉터리의 실행가능 파일 생성·웹셸 접근 패턴. 완화: 확장자 허용목록·실행권한 제거·저장소 분리·콘텐츠 검증.

- 출처(검증): https://portswigger.net/web-security/file-upload
