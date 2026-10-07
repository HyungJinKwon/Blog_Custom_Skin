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

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### RFC 9293 TCP
- 출처: https://datatracker.ietf.org/doc/html/rfc9293
- 승격일: 2026-10-07
- 요약: This document specifies the Transmission Control Protocol (TCP). TCP is an important transport-layer protocol in the Internet protocol stack, and it has continuously evolved over decades of use and growth of the Internet. Over this time, a number of changes have been made to TCP as it was specified in RFC 793, though these have only been documented in a piecemeal fashion. This document collects and brings those changes together with the protocol specification from RFC 793. This document obsolete
