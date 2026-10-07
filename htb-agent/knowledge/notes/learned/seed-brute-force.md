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

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### ATT&CK T1110 Brute Force
- 출처: https://attack.mitre.org/techniques/T1110/
- 승격일: 2026-10-07
- 요약: Brute Force Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.[1] Without knowledge of the password for an account or set of accounts, an adversary may systematically guess the password using a repetitive or iterative mechanism.[2] Brute forcing passwords can take place via interaction with a service that will check the validity of those credentials or offline against previously acquired credential data, such as
