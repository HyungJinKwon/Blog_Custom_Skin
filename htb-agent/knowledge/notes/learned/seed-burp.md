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
