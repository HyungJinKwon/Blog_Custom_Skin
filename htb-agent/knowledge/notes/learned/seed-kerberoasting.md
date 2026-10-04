# 학습 시드: kerberoasting (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn kerberoasting` 로 갱신.

SPN이 설정된 도메인 서비스 계정의 TGS-REP 티켓을 요청해 그 암호화 블록(계정 비밀번호 파생 키)을 오프라인 크랙한다(hashcat -m 13100). 도메인 사용자 인증만 있으면 가능. 탐지: 4769 급증·RC4 요청. 완화: 긴 랜덤 gMSA, AES 강제.

- 출처(검증): https://attack.mitre.org/techniques/T1558/003/
