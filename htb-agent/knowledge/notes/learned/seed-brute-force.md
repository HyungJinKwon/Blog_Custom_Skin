# 학습 시드: brute-force (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn brute-force` 로 갱신.

ATT&CK T1110. 자격 추측 공격: 패스워드 추측·사전·크리덴셜 스터핑·패스워드 스프레이(소수 암호×다수 계정으로 잠금 회피). 도구: hydra·medusa·netexec·kerbrute. 블루팀: 4625 급증, 단일 암호 다계정(스프레이) 패턴, SMB/LDAP/Kerberos 사전인증 실패(4771) 상관. 완화: 잠금정책·MFA·스프레이 탐지룰.

- 출처(검증): https://attack.mitre.org/techniques/T1110/
