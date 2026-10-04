# 학습 시드: pass-the-hash (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn pass-the-hash` 로 갱신.

평문 대신 NTLM 해시로 인증(NTLM 챌린지-응답). netexec -H / impacket -hashes. 로컬 관리자 해시 재사용 시 횡적 이동. 완화: LAPS, 제한 관리모드, SMB 서명.

- 출처(검증): https://attack.mitre.org/techniques/T1550/002/
