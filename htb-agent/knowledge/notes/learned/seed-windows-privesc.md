# 학습 시드(심화): windows-privesc

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn windows-privesc`. P1: 머신별 라이트업 미참조.

## 개요
윈도우 권한상승: 로컬 열거 기반 벡터 총람.

## 핵심 기법 · 열거
- 서비스 오구성(약한 권한·언쿼티드 경로·바이너리 교체)
- 토큰 권한(SeImpersonate→Potato 류, SeBackup/SeRestore)
- AlwaysInstallElevated·자동실행·저장 자격(cmdkey·레지스트리)
- UAC 우회·DLL 하이재킹·스케줄작업

## 표준 도구 · 명령
```
whoami /priv ; whoami /all
.\winPEASx64.exe ; .\PrintSpoofer.exe -i -c cmd  # SeImpersonate
reg query HKLM\...\Installer /v AlwaysInstallElevated
sc qc <svc> ; accesschk.exe -uwcqv <user> <svc>
```

## 블루팀 탐지
토큰 조작·서비스 바이너리 교체(7045)·비정상 권한 사용·Potato 패턴.

## 완화
서비스 권한 정리·언쿼티드 경로 수정·토큰권한 최소화·LAPS·패치.

- 출처(검증): https://attack.mitre.org/tactics/TA0004/
