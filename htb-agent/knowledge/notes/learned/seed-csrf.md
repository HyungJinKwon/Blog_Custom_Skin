# 학습 시드(심화): csrf

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn csrf`. P1: 머신별 라이트업 미참조.

## 개요
사이트간 요청 위조: 피해자 인증 세션으로 의도치 않은 상태변경 요청 강제. 쿠키 자동전송 악용.

## 핵심 기법 · 열거
- 성립조건: 쿠키 기반 세션 + 예측가능 요청 + 상태변경 액션
- GET/POST 자동제출 폼·이미지 태그·fetch
- 토큰 우회: 토큰 미검증·예측가능·세션 미바인딩·메서드 변경
- SameSite 우회(GET 전환·서브도메인)

## 표준 도구 · 명령
```
<form action='http://<target>/changeemail' method=POST>
  <input name=email value=attacker@evil.com></form><script>document.forms[0].submit()</script>
```

## 블루팀 탐지
상태변경 요청의 교차출처 Origin/Referer. 토큰 없는 POST. 비정상 참조元.

## 완화
CSRF 토큰(동기화/이중제출)·SameSite=Lax/Strict·Origin 검증·민감작업 재인증.

- 출처(검증): https://portswigger.net/web-security/csrf
