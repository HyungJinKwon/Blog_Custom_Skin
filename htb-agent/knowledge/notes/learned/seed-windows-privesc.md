# 학습 시드: windows-privesc (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn privilege-escalation` 로 갱신.

whoami /priv로 SeImpersonate 확인→PotatoFamily(PrintSpoofer/GodPotato). 서비스 권한 오구성·AlwaysInstallElevated·언쿼티드 서비스 경로·저장 자격증명(cmdkey). AD는 BloodHound로 경로 분석.

- 출처(검증): https://attack.mitre.org/tactics/TA0004/
