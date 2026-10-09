# 학습 시드(심화): ssrf

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn ssrf`. P1: 머신별 라이트업 미참조.

## 개요
서버측 요청 위조: 서버가 공격자 지정 URL 로 요청하게 만든다. 내부망 접근·클라우드 메타데이터 자격탈취. CWE-918.

## 핵심 기법 · 열거
- 내부망 스캔·내부 서비스 접근(localhost·사설대역)
- 클라우드 메타데이터: AWS 169.254.169.254/latest/meta-data/iam/security-credentials/ (IMDSv1)
- GCP metadata.google.internal + Metadata-Flavor:Google 헤더
- 우회: 리다이렉트·DNS 리바인딩·대체표기(10진 IP·[::])·URL 파서 혼동
- 프로토콜 스머글링: gopher:// 로 내부 Redis/MySQL 공격

## 표준 도구 · 명령
```
url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
url=http://127.0.0.1:6379/  (내부 Redis)
url=http://[::ffff:127.0.0.1]/   # 파서 우회
url=gopher://127.0.0.1:6379/_<redis-payload>
```

## 블루팀 탐지
아웃바운드에 169.254.169.254·내부 IP 요청. DNS 리바인딩(짧은 TTL). 비정상 gopher/file 스킴.

## 완화
아웃바운드 허용목록·IMDSv2(토큰 필수)·메타데이터 차단·스킴/호스트 검증·리다이렉트 차단.

- 출처(검증): https://portswigger.net/web-security/ssrf

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### PortSwigger SSRF
- 출처: https://portswigger.net/web-security/ssrf
- 승격일: 2026-10-07
- 요약: Server-side request forgery (SSRF) In this section we explain what server-side request forgery (SSRF) is, and describe some common examples. We also show you how to find and exploit SSRF vulnerabilities. What is SSRF? Server-side request forgery is a web security vulnerability that allows an attacker to cause the server-side application to make requests to an unintended location. In a typical SSRF attack, the attacker might cause the server to make a connection to internal-only services within t

### OWASP SSRF
- 출처: https://community.owasp.org/attacks/Server_Side_Request_Forgery
- 승격일: 2026-10-07
- 요약: Server Side Request Forgery Overview In a Server-Side Request Forgery (SSRF) attack, the attacker can abuse functionality on the server to read or update internal resources. The attacker can supply or modify a URL which the code running on the server will read or submit data to, and by carefully selecting the URLs, the attacker may be able to read server configuration such as AWS metadata, connect to internal services like http enabled databases or perform post requests towards internal services
