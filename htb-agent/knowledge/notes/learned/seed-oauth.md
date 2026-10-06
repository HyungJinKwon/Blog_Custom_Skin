# 학습 시드(심화): oauth

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn oauth`. P1: 머신별 라이트업 미참조.

## 개요
OAuth 2.0/OIDC 결함: 흐름 구현 오류로 계정탈취.

## 핵심 기법 · 열거
- redirect_uri 검증부실(토큰/코드 탈취)
- state 누락 → CSRF
- 암시적 흐름 토큰 노출·코드 재사용
- PKCE 미적용·open redirect 체인

## 표준 도구 · 명령
```
redirect_uri=https://attacker/callback   # 검증 우회 시도
응답의 code/token 을 공격자 콜백으로 탈취
```

## 블루팀 탐지
비정상 redirect_uri·code 재사용·state 불일치 로그.

## 완화
redirect_uri 정확일치·state/PKCE 필수·1회성 코드·짧은 만료.

- 출처(검증): https://portswigger.net/web-security/oauth
