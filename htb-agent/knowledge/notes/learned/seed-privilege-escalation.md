# 학습 시드(심화): privilege-escalation

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn privilege-escalation`. P1: 머신별 라이트업 미참조.

## 개요
권한상승(TA0004) 개요: 로컬 enum→오구성/취약점 악용으로 상위권한. 상세는 linux/windows-privesc.

## 핵심 기법 · 열거
- 리눅스: SUID/sudo/cron/capabilities/커널/PATH/쓰기가능 서비스
- 윈도우: 서비스 오구성·토큰·AlwaysInstallElevated·언쿼티드 경로·자격
- 자동 enum→후보 식별→검증

## 표준 도구 · 명령
```
# 리눅스: linpeas.sh ; sudo -l ; find / -perm -4000 2>/dev/null
# 윈도우: winPEAS.exe ; whoami /priv ; seatbelt
```

## 블루팀 탐지
비정상 권한승격·SUID 실행·토큰조작·서비스 바이너리 교체.

## 완화
최소권한·패치·오구성 점검·정기 enum·CIS 벤치마크.

- 출처(검증): https://attack.mitre.org/tactics/TA0004/
