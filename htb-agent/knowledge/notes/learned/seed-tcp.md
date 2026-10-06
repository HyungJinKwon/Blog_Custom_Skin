# 학습 시드(심화): tcp

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn tcp`. P1: 머신별 라이트업 미참조.

## 개요
TCP: 전송계층. 스캔 원리·방화벽 응답 해석의 기초(RFC 9293).

## 핵심 기법 · 열거
- 3방향 핸드셰이크·상태머신·플래그(SYN/ACK/FIN/RST)
- 스캔 유형: SYN(하프오픈)/connect/FIN/NULL/XMAS/ACK(방화벽 매핑)

## 표준 도구 · 명령
```
nmap -sS <target>   # SYN
nmap -sA <target>   # ACK(방화벽 규칙 추론)
hping3 -S <target> -p 80   # 수동 프로브
```

## 블루팀 탐지
비정상 플래그조합(NULL/XMAS)·하프오픈 스캔·RST 급증.

## 완화
상태기반 방화벽·IDS·불필요 포트 차단.

- 출처(검증): https://datatracker.ietf.org/doc/html/rfc9293
