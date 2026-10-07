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

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### MDN CORS
- 출처: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
- 승격일: 2026-10-07
- 요약: Cross-Origin Resource Sharing (CORS) Baseline Widely available This feature is well established and works across many devices and browser versions. It’s been available across browsers since July 2015. See full compatibility Learn more Cross-Origin Resource Sharing (CORS) is an HTTP-header based mechanism that allows a server to indicate any origins (domain, scheme, or port) other than its own from which a browser should permit loading resources. CORS also relies on a mechanism by which browsers

### PortSwigger CORS
- 출처: https://portswigger.net/web-security/cors
- 승격일: 2026-10-07
- 요약: Cross-origin resource sharing (CORS) In this section, we will explain what cross-origin resource sharing (CORS) is, describe some common examples of cross-origin resource sharing based attacks, and discuss how to protect against these attacks. This topic was written in collaboration with PortSwigger Research, who popularized this attack class with the presentation Exploiting CORS misconfigurations for Bitcoins and bounties. What is CORS (cross-origin resource sharing)? Cross-origin resource shar
