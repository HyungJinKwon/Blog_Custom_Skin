# 학습 시드(심화): access-control

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn access-control`. P1: 머신별 라이트업 미참조.

## 개요
접근통제 결함(IDOR/권한우회): 인가 검증 누락. CWE-639/284.

## 핵심 기법 · 열거
- 수평: 타 사용자 객체 접근(id 치환)
- 수직: 관리기능 강제 브라우징(/admin)
- 메서드/파라미터 조작·Referer 기반 통제 우회
- 질량 할당(mass assignment)로 role 설정

## 표준 도구 · 명령
```
/account?id=124   # 타 사용자
ffuf -u <url>/FUZZ -w admin-paths.txt   # 강제 브라우징
PUT {"role":"admin"}   # 질량 할당
```

## 블루팀 탐지
동일세션 다수 객체ID 순회·403 급증·권한 불일치 접근.

## 완화
서버측 세션기준 인가·객체소유 검증·거부기본·화이트리스트 바인딩.

- 출처(검증): https://portswigger.net/web-security/access-control
