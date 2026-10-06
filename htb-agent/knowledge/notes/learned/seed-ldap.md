# 학습 시드(심화): ldap

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn ldap`. P1: 머신별 라이트업 미참조.

## 개요
LDAP(389/636): AD 디렉터리 질의. 사용자·그룹·속성·ACL 열거 경로.

## 핵심 기법 · 열거
- 익명/인증 바인드로 객체 열거
- 사용자 description 의 암호·속성 수집
- ldap signing/channel binding 미설정 악용(릴레이)

## 표준 도구 · 명령
```
ldapsearch -x -H ldap://<target> -s base namingcontexts
ldapsearch -x -H ldap://<dc> -D 'user@d' -w pass -b 'dc=d,dc=local'
nxc ldap <dc> -u user -p pass --users
```

## 블루팀 탐지
대량 LDAP 조회·익명 바인드·비정상 속성 수집.

## 완화
익명 바인드 차단·LDAP 서명/채널바인딩·최소권한·민감속성 보호.

- 출처(검증): https://datatracker.ietf.org/doc/html/rfc4511
