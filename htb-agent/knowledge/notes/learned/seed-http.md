# 학습 시드(심화): http

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn http`. P1: 머신별 라이트업 미참조.

## 개요
HTTP(80/443): 웹 공격면의 기반. 디렉터리·vhost·기술스택 열거.

## 핵심 기법 · 열거
- 디렉터리/파일 퍼징·vhost 열거·robots/소스 분석
- 기술 식별(헤더·whatweb)·기본자격·백업파일(.bak/.git)
- 메서드(PUT/DELETE)·헤더 조작

## 표준 도구 · 명령
```
ffuf -u http://<target>/FUZZ -w raft-medium.txt
ffuf -u http://<target>/ -H 'Host: FUZZ.<target>' -w subs.txt   # vhost
whatweb http://<target> ; nikto -h http://<target>
curl -s http://<target>/.git/HEAD
```

## 블루팀 탐지
비정상 404 급증(퍼징)·스캐너 UA·민감경로(.git/.env) 접근.

## 완화
디렉터리 리스팅 비활성·백업/.git 제거·인증·WAF·최소 헤더 노출.

- 출처(검증): https://developer.mozilla.org/en-US/docs/Web/HTTP

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### HTTP(MDN)
- 출처: https://developer.mozilla.org/en-US/docs/Web/HTTP
- 승격일: 2026-10-07
- 요약: HTTP: Hypertext Transfer Protocol HTTP is an application-layer protocol for transmitting hypermedia documents, such as HTML. It was designed for communication between web browsers and web servers, but it can also be used for other purposes, such as machine-to-machine communication, programmatic access to APIs, and more. HTTP follows a classical client-server model, with a client opening a connection to make a request, then waiting until it receives a response from the server. HTTP is a stateless

### RFC 9110 HTTP Semantics
- 출처: https://datatracker.ietf.org/doc/html/rfc9110
- 승격일: 2026-10-07
- 요약: The Hypertext Transfer Protocol (HTTP) is a stateless application-level protocol for distributed, collaborative, hypertext information systems. This document describes the overall architecture of HTTP, establishes common terminology, and defines aspects of the protocol that are shared by all versions. In this definition are core protocol elements, extensibility mechanisms, and the "http" and "https" Uniform Resource Identifier (URI) schemes.¶ This document updates RFC 3864 and obsoletes RFCs 281
