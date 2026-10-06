# 학습 시드(심화): cors

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn cors`. P1: 머신별 라이트업 미참조.

## 개요
CORS 설정 오류: 교차출처 자격포함 요청 허용으로 민감데이터 탈취.

## 핵심 기법 · 열거
- Origin 반사 + Allow-Credentials:true
- null 출처 신뢰(iframe sandbox)
- 와일드카드 서브도메인·정규식 결함

## 표준 도구 · 명령
```
curl -H 'Origin: https://evil.com' -I <url>/api/me
# 응답에 ACAO: https://evil.com + ACAC: true 면 취약
```

## 블루팀 탐지
응답 ACAO 가 요청 Origin 반사 + credentials. 비정상 교차출처 API 접근.

## 완화
출처 허용목록 엄격검증·credentials 와 와일드카드 병용 금지·정규식 앵커.

- 출처(검증): https://portswigger.net/web-security/cors
