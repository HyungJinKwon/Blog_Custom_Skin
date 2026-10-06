# 학습 시드(심화): password-cracking

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn password-cracking`. P1: 머신별 라이트업 미참조.

## 개요
패스워드 크래킹(T1110.002): 수집 해시를 오프라인 크랙.

## 핵심 기법 · 열거
- 해시 식별(hashid)·모드 선택(hashcat -m)
- 규칙(best64)·마스크·사전(rockyou)
- 주요 모드: 1000 NTLM,1800 sha512crypt,13100 Kerberoast,18200 AS-REP,16500 JWT,22000 WPA

## 표준 도구 · 명령
```
hashid '<hash>' ; hashcat --example-hashes | grep -i ntlm
hashcat -m 1000 ntlm.txt rockyou.txt -r rules/best64.rule
john --format=sha512crypt --wordlist=rockyou.txt shadow.txt
```

## 블루팀 탐지
(오프라인 활동 — 호스트 측 탐지 제한). 선행 해시 덤프 탐지가 핵심.

## 완화
강한/긴 암호·느린 해시(bcrypt/argon2)·솔트·유출암호 차단.

- 출처(검증): https://attack.mitre.org/techniques/T1110/002/
