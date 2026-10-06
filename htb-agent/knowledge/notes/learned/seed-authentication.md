# 학습 시드: authentication (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn authentication` 로 갱신.

인증 결함: 약한 자격·크리덴셜 스터핑·사용자명 열거(응답/타이밍 차이)·취약한 2FA·비밀번호 재설정 로직 결함. 브루트포스 대상 1순위. 블루팀: 반복 실패(Windows 4625/4771), 분산 IP 스터핑, 짧은 간격 다계정 시도 탐지. 완화: 레이트리밋·계정잠금·균일 오류메시지·MFA·안전한 재설정 토큰(1회성·만료).

- 출처(검증): https://portswigger.net/web-security/authentication
