# 학습 시드(심화): smb

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn smb`. P1: 머신별 라이트업 미참조.

## 개요
SMB/CIFS(139/445): 윈도우 파일공유. HTB 윈도우 초기침투·열거 핵심.

## 핵심 기법 · 열거
- 널세션·게스트로 공유/사용자 열거
- RID 브루트로 사용자 enum
- 쓰기가능 공유·설정파일·자격 노출
- EternalBlue(MS17-010) 등 RCE
- 자격 보유 시 원격실행(psexec/wmiexec/smbexec)

## 표준 도구 · 명령
```
nxc smb <target> -u '' -p '' --shares            # 널세션 공유
nxc smb <target> -u user -p pass --users --rid-brute
smbclient -N -L //<target>/ ; smbclient //<target>/share -N
nxc smb <target> -u user -p pass -x 'whoami'     # 원격실행
impacket-psexec user:pass@<target>
```

## 블루팀 탐지
4624 Type3 원격로그온·관리공유(ADMIN$/C$) 접근·7045 서비스생성(psexec)·SMB1 사용.

## 완화
SMB 서명 강제·SMBv1 비활성·널세션 차단·최소권한 공유·LAPS.

- 출처(검증): https://attack.mitre.org/techniques/T1021/002/

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### Wireshark SMB
- 출처: https://wiki.wireshark.org/SMB
- 승격일: 2026-10-07
- 요약: Server Message Block Protocol (SMB) The Server Message Block protocol, or "SMB", is a remote file access protocol originally specified by Microsoft, IBM, and Intel. It's also referred to as the Common Internet File System, or "CIFS". It's one of the protocols most commonly used by DOS and Windows machines to access files on a file server. Current versions of Windows, and some older versions of Windows, include both client and server code for SMB/CIFS; clients and servers were also available for

### ATT&CK SMB/Windows Admin Shares
- 출처: https://attack.mitre.org/techniques/T1021/002/
- 승격일: 2026-10-07
- 요약: Remote Services: SMB/Windows Admin Shares Adversaries may use Valid Accounts to interact with a remote network share using Server Message Block (SMB). The adversary may then perform actions as the logged-on user. SMB is a file, printer, and serial port sharing protocol for Windows machines on the same network or domain. Adversaries may use SMB to interact with file shares, allowing them to move laterally throughout a network. Linux and macOS implementations of SMB typically use Samba. Windows sy
