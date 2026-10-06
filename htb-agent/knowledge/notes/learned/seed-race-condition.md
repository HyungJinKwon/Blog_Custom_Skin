# 학습 시드(심화): race-condition

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn race-condition`. P1: 머신별 라이트업 미참조.

## 개요
경쟁조건(TOCTOU): 동시요청으로 검사-사용 간극 악용.

## 핵심 기법 · 열거
- 한도우회(쿠폰/출금 중복)·중복가입·제한우회
- 단일패킷 공격(HTTP/2)·last-byte 동기화

## 표준 도구 · 명령
```
# Turbo Intruder / ffuf 로 동시 다발 요청
for i in $(seq 30); do curl <url>/redeem & done
```

## 블루팀 탐지
동일리소스 초단시간 다중요청·음수/중복 잔액 이벤트.

## 완화
원자적 연산·DB 잠금(SELECT FOR UPDATE)·멱등성 키·유니크 제약.

- 출처(검증): https://portswigger.net/web-security/race-conditions
