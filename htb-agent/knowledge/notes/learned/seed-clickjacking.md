# 학습 시드(심화): clickjacking

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn clickjacking`. P1: 머신별 라이트업 미참조.

## 개요
클릭재킹(UI 리드레싱): 투명 iframe 로 피해자 클릭을 탈취.

## 핵심 기법 · 열거
- 프레임 삽입 가능 + 민감 액션 1클릭일 때 성립
- 드래그앤드롭·커서재킹 변종

## 표준 도구 · 명령
```
<iframe src='http://<target>/transfer' style=opacity:0></iframe>
```

## 블루팀 탐지
민감 페이지의 X-Frame-Options/CSP frame-ancestors 부재.

## 완화
X-Frame-Options:DENY·CSP frame-ancestors 'self'·중요작업 확인단계.

- 출처(검증): https://portswigger.net/web-security/clickjacking

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### PortSwigger Clickjacking
- 출처: https://portswigger.net/web-security/clickjacking
- 승격일: 2026-10-07
- 요약: Clickjacking (UI redressing) In this section we will explain what clickjacking is, describe common examples of clickjacking attacks and discuss how to protect against these attacks. What is clickjacking? Clickjacking is an interface-based attack in which a user is tricked into clicking on actionable content on a hidden website by clicking on some other content in a decoy website. Consider the following example: A web user accesses a decoy website (perhaps this is a link provided by an email) and
