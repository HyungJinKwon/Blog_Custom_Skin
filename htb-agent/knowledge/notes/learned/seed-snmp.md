# 학습 시드(심화): snmp

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn snmp`. P1: 머신별 라이트업 미참조.

## 개요
SNMP(161/udp): 네트워크 관리. 기본 community 로 시스템정보 노출(v1/v2c 평문).

## 핵심 기법 · 열거
- community(public/private) 추측
- 시스템/프로세스/사용자/라우팅/설치SW 노출
- 쓰기 community 로 설정 변경

## 표준 도구 · 명령
```
onesixtyone <target> community.txt
snmpwalk -v2c -c public <target>
snmpwalk -v2c -c public <target> 1.3.6.1.4.1.77.1.2.25  # 사용자
```

## 블루팀 탐지
기본 community 접근·대량 OID 조회·v1/v2c 평문.

## 완화
SNMPv3(인증/암호)·community 변경·접근제한·불필요 비활성.

- 출처(검증): https://datatracker.ietf.org/doc/html/rfc1157
