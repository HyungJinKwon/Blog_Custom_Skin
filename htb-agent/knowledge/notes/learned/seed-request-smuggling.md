# 학습 시드(심화): request-smuggling

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn request-smuggling`. P1: 머신별 라이트업 미참조.

## 개요
HTTP 요청 밀반입: 프론트/백엔드 길이해석 불일치로 요청경계 조작.

## 핵심 기법 · 열거
- CL.TE / TE.CL / TE.TE 변종
- HTTP/2 다운그레이드 스머글링
- 활용: 캐시오염·인증우회·요청탈취·내부헤더 주입

## 표준 도구 · 명령
```
# Burp HTTP Request Smuggler 로 탐지
Transfer-Encoding: chunked + Content-Length 모호 조합
```

## 블루팀 탐지
모호한 CL/TE 헤더 동시 존재·비정상 파이프라인·응답 불일치.

## 완화
일관된 파서·HTTP/2 end-to-end·모호헤더 거부·프론트 정규화.

- 출처(검증): https://portswigger.net/web-security/request-smuggling

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### CWE-444 HTTP Request Smuggling
- 출처: https://cwe.mitre.org/data/definitions/444.html
- 승격일: 2026-10-07
- 요약: CWE-444: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') — The product acts as an intermediary HTTP agent (such as a proxy or firewall) in the data flow between two entities such as a client and server, but it does not interpret malformed HTTP requests or responses in ways that are consistent with how the messages will be processed by those entities that are at the ultimate destination. Extended Description HTTP requests or responses ("messages") can be malformed

### PortSwigger HTTP Request Smuggling
- 출처: https://portswigger.net/web-security/request-smuggling
- 승격일: 2026-10-07
- 요약: HTTP request smuggling In this section, we'll explain HTTP request smuggling attacks and describe how common request smuggling vulnerabilities can arise. Labs If you're already familiar with HTTP request smuggling and just want to practice on a series of deliberately vulnerable sites, check out the link below for an overview of all labs in this topic. View all HTTP request smuggling labs What is HTTP request smuggling? HTTP request smuggling is a technique for interfering with the way a web site
