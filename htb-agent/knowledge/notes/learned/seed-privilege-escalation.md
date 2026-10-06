# 학습 시드: privilege-escalation (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn privilege-escalation` 로 갱신.

ATT&CK TA0004. 권한상승 전술 개요: 로컬 enum→오구성·취약점 악용으로 상위권한. 리눅스(SUID/sudo/cron/capabilities/커널)·윈도우(서비스 오구성·토큰·AlwaysInstallElevated·언쿼티드 경로). 상세는 seed-linux-privesc·seed-windows-privesc 참고. 블루팀: 비정상 권한승격·SUID 실행·토큰조작 탐지. 완화: 최소권한·패치·오구성 점검.

- 출처(검증): https://attack.mitre.org/tactics/TA0004/
