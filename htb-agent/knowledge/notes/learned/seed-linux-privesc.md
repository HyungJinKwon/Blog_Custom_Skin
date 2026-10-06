# 학습 시드(심화): linux-privesc

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn linux-privesc`. P1: 머신별 라이트업 미참조.

## 개요
리눅스 권한상승: 로컬 열거 기반 벡터 총람. HTB root 획득 핵심.

## 핵심 기법 · 열거
- sudo -l(NOPASSWD·GTFOBins)·SUID/SGID 바이너리(GTFOBins)
- cron 작업(쓰기가능 스크립트·와일드카드)·PATH 하이재킹
- capabilities(cap_setuid)·쓰기가능 /etc/passwd·쓰기가능 서비스 유닛
- 커널 익스플로잇(PwnKit/DirtyPipe)·NFS no_root_squash·docker 그룹

## 표준 도구 · 명령
```
sudo -l ; find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null ; cat /etc/crontab ; ls -la /etc/cron*
./linpeas.sh ; # GTFOBins 에서 해당 바이너리 검색
# NFS: mount -o rw <t>:/share /mnt ; SUID 바이너리 심기
```

## 블루팀 탐지
SUID 비정상 실행·sudo 남용·cron 스크립트 변조·커널 LPE 시그니처.

## 완화
sudo 최소화·SUID 정리·cron 권한·커널 패치·no_root_squash 제거.

- 출처(검증): https://attack.mitre.org/tactics/TA0004/
