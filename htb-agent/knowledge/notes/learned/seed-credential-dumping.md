# 학습 시드(심화): credential-dumping

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn credential-dumping`. P1: 머신별 라이트업 미참조.

## 개요
자격 덤프(T1003): 메모리/디스크에서 자격 추출.

## 핵심 기법 · 열거
- LSASS(mimikatz/comsvcs/procdump)·SAM+SYSTEM 하이브
- NTDS.dit(DCSync/vssadmin)·/etc/shadow·브라우저·앱 저장자격

## 표준 도구 · 명령
```
impacket-secretsdump -sam sam -system system LOCAL
nxc smb <t> -u a -p b --sam --lsa
procdump -ma lsass.exe lsass.dmp ; pypykatz lsa minidump lsass.dmp
```

## 블루팀 탐지
LSASS 핸들 접근(Sysmon 10)·vssadmin/ntdsutil 실행·SAM 비정상 접근.

## 완화
Credential Guard·LSA 보호(RunAsPPL)·최소권한·LAPS.

- 출처(검증): https://attack.mitre.org/techniques/T1003/

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### ATT&CK T1003 OS Credential Dumping
- 출처: https://attack.mitre.org/techniques/T1003/
- 승격일: 2026-10-07
- 요약: OS Credential Dumping Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password. Credentials can be obtained from OS caches, memory, or structures.[1] Credentials can then be used to perform Lateral Movement and access restricted information. Several of the tools mentioned in associated sub-techniques may be used by both adversaries and professional security testers. Additional custom tools likely exist as
