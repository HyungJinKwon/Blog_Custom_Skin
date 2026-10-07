# 학습 시드(심화): lateral-movement

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn lateral-movement`. P1: 머신별 라이트업 미참조.

## 개요
횡이동(TA0008): 획득 자격으로 내부 호스트 이동.

## 핵심 기법 · 열거
- PsExec/WMI/WinRM/RDP/SMB·PtH/PtT·SSH 피벗
- BloodHound 경로분석·ACL 남용 체인

## 표준 도구 · 명령
```
impacket-psexec user:pass@<host> ; impacket-wmiexec ...
evil-winrm -i <host> -u user -p pass
nxc smb <subnet> -u user -p pass            # 자격 재사용 범위
```

## 블루팀 탐지
4624 Type3/10·관리공유 접근·7045 서비스생성·비정상 원격실행.

## 완화
분할·LAPS·관리자 계층화·최소권한·원격관리 제한.

- 출처(검증): https://attack.mitre.org/tactics/TA0008/

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### ATT&CK TA0008 Lateral Movement
- 출처: https://attack.mitre.org/tactics/TA0008/
- 승격일: 2026-10-07
- 요약: Lateral Movement The adversary is trying to move through your environment. Lateral Movement consists of techniques that adversaries use to enter and control remote systems on a network. Following through on their primary objective often requires exploring the network to find their target, then pivoting through multiple systems and accounts to gain access to it. Adversaries might install their own remote access tools to accomplish Lateral Movement or use legitimate credentials with native network
