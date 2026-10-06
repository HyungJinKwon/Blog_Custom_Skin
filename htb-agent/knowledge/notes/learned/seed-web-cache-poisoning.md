# 학습 시드(심화): web-cache-poisoning

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn web-cache-poisoning`. P1: 머신별 라이트업 미참조.

## 개요
웹캐시 오염: 캐시키 미포함 입력으로 악성응답을 캐시에 저장→타 사용자 서빙.

## 핵심 기법 · 열거
- 언키드 헤더(X-Forwarded-Host)로 XSS/리다이렉트 전파
- 캐시키 정규화 결함·fat GET

## 표준 도구 · 명령
```
Param Miner 로 언키드 입력 탐색
X-Forwarded-Host: evil.com  # 응답 반영+캐시 확인
```

## 블루팀 탐지
캐시 HIT 응답에 요청별 입력 반영·비정상 Vary.

## 완화
키 정규화·언키드 입력 제거·Vary 정확설정·민감응답 no-store.

- 출처(검증): https://portswigger.net/web-security/web-cache-poisoning
