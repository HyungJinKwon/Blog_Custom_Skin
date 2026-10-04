# 학습 시드: dcsync (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn dcsync` 로 갱신.

DS-Replication 권한(Replicating Directory Changes) 보유 계정이 DRSUAPI로 DC에 복제를 요청해 KRBTGT/계정 해시를 덤프. impacket-secretsdump --just-dc. → Golden Ticket. 탐지: 비-DC의 복제 요청(4662).

- 출처(검증): https://attack.mitre.org/techniques/T1003/006/
