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
