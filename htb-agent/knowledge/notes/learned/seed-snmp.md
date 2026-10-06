# 학습 시드: snmp (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn snmp` 로 갱신.

RFC 1157. SNMP(161/udp). 기본 커뮤니티스트링(public/private)으로 시스템정보·사용자·프로세스·라우팅 노출(특히 v1/v2c 평문). 열거: snmpwalk·onesixtyone. 블루팀: 기본 커뮤니티 접근·대량 OID 조회 탐지. 완화: v3(인증/암호)·커뮤니티 변경·접근제한.

- 출처(검증): https://datatracker.ietf.org/doc/html/rfc1157
