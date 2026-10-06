# 학습 시드: exfiltration (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn exfiltration` 로 갱신.

ATT&CK TA0010. 데이터 반출: C2 채널·대체프로토콜(DNS/ICMP 터널)·클라우드/웹서비스·물리매체. 압축·암호화로 은닉. 블루팀: 비정상 대용량 아웃바운드, DNS 질의량 급증, 비승인 클라우드 업로드 탐지. 완화: DLP·아웃바운드 통제·egress 필터.

- 출처(검증): https://attack.mitre.org/tactics/TA0010/
