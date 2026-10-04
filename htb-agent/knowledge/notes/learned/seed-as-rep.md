# 학습 시드: as-rep (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn as-rep` 로 갱신.

사전인증(Pre-Auth)이 비활성(DONT_REQ_PREAUTH)인 계정은 비인증 상태로 AS-REP를 받아 오프라인 크랙 가능(hashcat -m 18200). impacket-GetNPUsers. 완화: 사전인증 강제, 강한 암호.

- 출처(검증): https://attack.mitre.org/techniques/T1558/004/
