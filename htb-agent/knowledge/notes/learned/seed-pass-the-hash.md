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

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### CAPEC-644 Use of Captured Hashes
- 출처: https://capec.mitre.org/data/definitions/644.html
- 승격일: 2026-10-07
- 요약: Attack Pattern ID: 644 Abstraction: Detailed Description An adversary obtains (i.e. steals or purchases) legitimate Windows domain credential hash values to access systems within the domain that leverage the Lan Man (LM) and/or NT Lan Man (NTLM) authentication protocols. Extended Description When authenticating via LM or NTLM, an authenticating account's plaintext credentials are not required by the protocols for successful authentication. Instead, the hashed credentials are used to determine if

### ATT&CK T1550.002 Pass the Hash
- 출처: https://attack.mitre.org/techniques/T1550/002/
- 승격일: 2026-10-07
- 요약: Use Alternate Authentication Material: Pass the Hash Adversaries may "pass the hash" using stolen password hashes to move laterally within an environment, bypassing normal system access controls. Pass the hash (PtH) is a method of authenticating as a user without having access to the user's cleartext password. This method bypasses standard authentication steps that require a cleartext password, moving directly into the portion of the authentication that uses the password hash. When performing Pt
