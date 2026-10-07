# 학습 시드(심화): burp

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn burp`. P1: 머신별 라이트업 미참조.

## 개요
Burp Suite: 웹 프록시·공격 플랫폼. 요청 가로채기·수정·자동화.

## 핵심 기법 · 열거
- Proxy(가로채기)·Repeater(수동 재전송)·Intruder(퍼징)·Decoder·Comparer
- 확장(BApp): Param Miner·Autorize·HTTP Smuggler
- 스코프 설정·매치&리플레이스

## 표준 도구 · 명령
```
# 브라우저 프록시 127.0.0.1:8080 → CA 설치
Repeater: 요청 수동 조작·재전송
Intruder: 파라미터 퍼징(Sniper/Cluster bomb)
```

## 블루팀 탐지
(공격자 도구 — 대상 측에선 비정상 반복/변조 요청으로 관찰).

## 완화
(도구). 방어는 각 취약점 완화 참조.

- 출처(검증): https://portswigger.net/burp/documentation

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### Burp Suite 문서
- 출처: https://portswigger.net/burp/documentation
- 승격일: 2026-10-07
- 요약: DASTProfessionalCommunity Edition Burp Suite documentation Read time: 1 Minute This documentation describes the functionality of all editions of Burp Suite and related components. Use the links below to get started: Burp Suite Professional and Community editions Burp Suite DAST Burp Scanner Burp Collaborator Full documentation contents Note Like any security testing software, Burp Suite contains functionality that can damage target systems. Testing for security flaws inherently involves interact

### Web Security Academy
- 출처: https://portswigger.net/web-security
- 승격일: 2026-10-07
- 요약: Boost your career The Web Security Academy is a strong step toward a career in cybersecurity. Flexible learning Learn anywhere, anytime, with free interactive labs and progress-tracking. Learn from experts Produced by a world-class team - led by the author of The Web Application Hacker's Handbook. New labs: AI-powered scanner vulnerabilities Learn how indirect prompt injection can be used to manipulate AI-powered web application scanners into performing unintended actions, exfiltrating sensitive
