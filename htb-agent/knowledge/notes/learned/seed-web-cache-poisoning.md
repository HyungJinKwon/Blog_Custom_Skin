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

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### OWASP Cache Poisoning
- 출처: https://community.owasp.org/attacks/Cache_Poisoning
- 승격일: 2026-10-07
- 요약: Cache Poisoning Description The impact of a maliciously constructed response can be magnified if it is cached either by a web cache used by multiple users or even the browser cache of a single user. If a response is cached in a shared web cache, such as those commonly found in proxy servers, then all users of that cache will continue to receive the malicious content until the cache entry is purged. Similarly, if the response is cached in the browser of an individual user, then that user will con

### PortSwigger Web Cache Poisoning
- 출처: https://portswigger.net/web-security/web-cache-poisoning
- 승격일: 2026-10-07
- 요약: Web cache poisoning In this section, we'll talk about what web cache poisoning is and what behaviors can lead to web cache poisoning vulnerabilities. We'll also look at some ways of exploiting these vulnerabilities and suggest ways you can reduce your exposure to them. What is web cache poisoning? Web cache poisoning is an advanced technique whereby an attacker exploits the behavior of a web server and cache so that a harmful HTTP response is served to other users. Fundamentally, web cache poiso
