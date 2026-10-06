# 학습 시드: command-injection (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn command-injection` 로 갱신.

OS 명령 주입: 사용자 입력이 셸 명령에 삽입되어 임의 명령 실행. 구분자 ; | & && || `cmd` $(cmd), 블라인드는 시간지연(sleep)·OOB(DNS/HTTP) 로 탐지. CWE-78. 블루팀: 웹프로세스의 비정상 자식프로세스(sh/bash/cmd) 생성, 아웃바운드 DNS 이상. 완화: 셸 미경유 API·인자 배열 실행·엄격 허용목록.

- 출처(검증): https://portswigger.net/web-security/os-command-injection
