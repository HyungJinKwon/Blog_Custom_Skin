# 학습 시드(심화): prototype-pollution

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn prototype-pollution`. P1: 머신별 라이트업 미참조.

## 개요
프로토타입 오염: __proto__/constructor 로 Object.prototype 오염→속성주입.

## 핵심 기법 · 열거
- 클라이언트: DOM XSS 가젯 체인
- 서버: 속성 밀반입→설정변경/RCE 가젯
- JSON 병합·쿼리파서 취약

## 표준 도구 · 명령
```
?__proto__[isAdmin]=true
{"__proto__":{"polluted":"yes"}}
```

## 블루팀 탐지
입력에 __proto__·constructor.prototype. 비정상 전역 속성 등장.

## 완화
Object.create(null)·Map·키 검증·Object.freeze·안전한 병합 라이브러리.

- 출처(검증): https://portswigger.net/web-security/prototype-pollution

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### OWASP Prototype Pollution Prevention
- 출처: https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html
- 승격일: 2026-10-07
- 요약: Prototype Pollution Prevention Cheat Sheet Explanation Prototype Pollution is a critical vulnerability that can allow attackers to manipulate an application's JavaScript objects and properties, leading to serious security issues such as unauthorized access to data, privilege escalation, and even remote code execution. For examples of why this is dangerous, see the links in the Other resources section below. Suggested protection mechanisms Use "new Set()" or "new Map()" Developers should use new

### PortSwigger Prototype Pollution
- 출처: https://portswigger.net/web-security/prototype-pollution
- 승격일: 2026-10-07
- 요약: What is prototype pollution? Prototype pollution is a JavaScript vulnerability that enables an attacker to add arbitrary properties to global object prototypes, which may then be inherited by user-defined objects. Although prototype pollution is often unexploitable as a standalone vulnerability, it lets an attacker control properties of objects that would otherwise be inaccessible. If the application subsequently handles an attacker-controlled property in an unsafe way, this can potentially be c
