# 학습 시드: access-control (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn access-control` 로 갱신.

접근통제 결함(IDOR/권한우회)은 인가 검증 누락으로 타 사용자 객체·관리기능에 접근하는 취약점. 수평(타 유저 데이터)·수직(권한상승) 구분. 패턴: 예측가능 ID(/account?id=123) 치환, 강제 브라우징(/admin), HTTP 메서드/파라미터 조작, Referer 기반 통제. 블루팀: 접근거부(403)·동일세션 다수 ID 순회 로그 이상탐지. CWE-639/CWE-284. 완화: 서버측 세션 기준 인가·객체소유 검증·거부기본(deny-by-default).

- 출처(검증): https://portswigger.net/web-security/access-control
