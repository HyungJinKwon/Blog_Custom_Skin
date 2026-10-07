# 학습 시드(심화): graphql

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn graphql`. P1: 머신별 라이트업 미참조.

## 개요
GraphQL API 공격: 인트로스펙션·과도조회·배칭 남용·인가누락.

## 핵심 기법 · 열거
- 인트로스펙션으로 전체 스키마 노출(__schema)
- 깊은 중첩/과도조회 DoS
- 배칭으로 레이트리밋/브루트포스 우회
- 필드 레벨 인가 누락(IDOR)

## 표준 도구 · 명령
```
{__schema{types{name fields{name}}}}          # 인트로스펙션
clairvoyance / graphw00f 로 스키마 추론·엔진 식별
엔드포인트: /graphql /api/graphql /v1/graphql
```

## 블루팀 탐지
인트로스펙션 질의·비정상 쿼리 깊이/배열 배치·단일 요청 다수 뮤테이션.

## 완화
프로덕션 인트로스펙션 차단·깊이/복잡도 제한·필드 인가·배치 제한.

- 출처(검증): https://portswigger.net/web-security/graphql

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### OWASP GraphQL Cheat Sheet
- 출처: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- 승격일: 2026-10-07
- 요약: GraphQL Cheat Sheet Introduction GraphQL is an open source query language originally developed by Facebook that can be used to build APIs as an alternative to REST and SOAP. It has gained popularity since its inception in 2012 because of the native flexibility it offers to those building and calling the API. There are GraphQL servers and clients implemented in various languages. Many companies use GraphQL including GitHub, Credit Karma, Intuit, and PayPal. This Cheat Sheet provides guidance on t

### PortSwigger GraphQL API
- 출처: https://portswigger.net/web-security/graphql
- 승격일: 2026-10-07
- 요약: GraphQL API vulnerabilities GraphQL vulnerabilities generally arise due to implementation and design flaws. For example, the introspection feature may be left active, enabling attackers to query the API in order to glean information about its schema. GraphQL attacks usually take the form of malicious requests that can enable an attacker to obtain data or perform unauthorized actions. These attacks can have a severe impact, especially if the user is able to gain admin privileges by manipulating q
