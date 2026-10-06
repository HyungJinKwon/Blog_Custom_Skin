# 학습 시드: lateral-movement (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn lateral-movement` 로 갱신.

ATT&CK TA0008. 횡이동: 획득자격으로 내부 호스트 이동 — PsExec/WMI/WinRM/RDP/SMB, Pass-the-Hash/Ticket, SSH 피벗. BloodHound 로 경로분석. 블루팀: 비정상 원격실행(4624 Type3/10), 관리공유 접근, 서비스생성(7045) 상관. 완화: 분할·LAPS·관리자 계층화·최소권한.

- 출처(검증): https://attack.mitre.org/tactics/TA0008/
