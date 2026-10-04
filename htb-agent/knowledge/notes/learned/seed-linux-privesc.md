# 학습 시드: linux-privesc (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn privilege-escalation` 로 갱신.

SUID(find / -perm -4000)·sudo -l(GTFOBins)·capabilities(getcap)·cron 쓰기·커널(Dirty Pipe CVE-2022-0847/Dirty COW CVE-2016-5195)·PwnKit CVE-2021-4034·Sudo Baron Samedit CVE-2021-3156 순으로 점검.

- 출처(검증): https://attack.mitre.org/tactics/TA0004/
