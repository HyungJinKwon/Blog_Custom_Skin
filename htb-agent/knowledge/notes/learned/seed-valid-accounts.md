# 학습 시드(심화): valid-accounts

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn valid-accounts`. P1: 머신별 라이트업 미참조.

## 개요
유효계정(T1078): 탈취·기본·휴면 자격으로 정상사용자처럼 접근.

## 핵심 기법 · 열거
- 초기접근·지속성·권한상승·회피 동시충족
- 기본/재사용 암호 흔함·패스워드 재사용 횡이동

## 표준 도구 · 명령
```
nxc smb <subnet> -u user -p pass            # 자격 재사용 범위 확인
evil-winrm -i <target> -u user -p pass
```

## 블루팀 탐지
비정상 시간/위치 로그인·휴면계정 활성화·불가능 이동(impossible travel).

## 완화
MFA·기본자격 제거·조건부접근·암호 재사용 차단.

- 출처(검증): https://attack.mitre.org/techniques/T1078/

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### ATT&CK T1078 Valid Accounts
- 출처: https://attack.mitre.org/techniques/T1078/
- 승격일: 2026-10-07
- 요약: Valid Accounts Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access, network devices, and remote desktop.[1] Compromised credentials may also gra
