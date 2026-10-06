# 학습 시드: prototype-pollution (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn prototype-pollution` 로 갱신.

JS 프로토타입 오염: __proto__/constructor/prototype 로 Object.prototype 오염→속성주입. 클라이언트(DOM XSS)·서버(속성 밀반입→RCE/우회). 블루팀: __proto__ 포함 입력·비정상 속성 탐지. 완화: Object.create(null)·입력키 검증·Map 사용·freeze.

- 출처(검증): https://portswigger.net/web-security/prototype-pollution
