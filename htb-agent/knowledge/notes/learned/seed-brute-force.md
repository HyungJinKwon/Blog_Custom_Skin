# 학습 시드(심화): brute-force

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn brute-force`. P1: 머신별 라이트업 미참조.

## 개요
브루트포스(T1110): 자격 추측(사전·스프레이·스터핑).

## 핵심 기법 · 열거
- 패스워드 스프레이(소수 암호×다수 계정)로 잠금 회피
- 서비스별: SSH·FTP·SMB·HTTP·RDP·WinRM
- 해시 오프라인 크랙 연계

## 표준 도구 · 명령
```
hydra -L users.txt -P rockyou.txt ssh://<target>
nxc smb <target> -u users.txt -p 'Spring2025!' --continue-on-success
kerbrute passwordspray -d <domain> users.txt 'Welcome1'
```

## 블루팀 탐지
4625 급증·단일암호 다계정(스프레이)·분산 IP 스터핑.

## 완화
잠금정책·MFA·스프레이 탐지룰·fail2ban·강한 암호정책.

- 출처(검증): https://attack.mitre.org/techniques/T1110/
