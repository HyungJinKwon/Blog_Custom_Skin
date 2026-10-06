# 학습 시드: credential-dumping (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn credential-dumping` 로 갱신.

ATT&CK T1003. 자격 탈취: LSASS 메모리(mimikatz/comsvcs), SAM/SYSTEM 하이브, NTDS.dit(DCSync/볼륨섀도), /etc/shadow, 브라우저·앱 저장자격. 횡이동·권한상승의 연료. 블루팀: LSASS 핸들 접근(Sysmon 10), ntdsutil/vssadmin 실행, 비정상 SAM 접근 탐지. 완화: Credential Guard·LSA 보호·최소권한.

- 출처(검증): https://attack.mitre.org/techniques/T1003/
