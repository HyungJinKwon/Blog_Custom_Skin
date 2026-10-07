# 학습 시드(심화): persistence

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn persistence`. P1: 머신별 라이트업 미참조.

## 개요
지속성(TA0003): 재부팅/로그아웃 후 접근 유지.

## 핵심 기법 · 열거
- 크론/스케줄작업·서비스·레지스트리 Run·시작프로그램
- SSH authorized_keys·WMI 구독·웹셸·계정생성·SUID 백도어

## 표준 도구 · 명령
```
echo '<pubkey>' >> ~/.ssh/authorized_keys
schtasks /create /tn upd /tr c:\x.exe /sc onlogon
(crontab -l; echo '* * * * * /tmp/s.sh')|crontab -
```

## 블루팀 탐지
자동실행 변경·신규 서비스(7045)·스케줄작업(4698)·authorized_keys 변경.

## 완화
기준선 모니터링·무결성 검사·자동실행 감사·키 관리.

- 출처(검증): https://attack.mitre.org/tactics/TA0003/

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### ATT&CK TA0003 Persistence
- 출처: https://attack.mitre.org/tactics/TA0003/
- 승격일: 2026-10-07
- 요약: Persistence The adversary is trying to maintain their foothold. Persistence consists of techniques that adversaries use to keep access to systems across restarts, changed credentials, and other interruptions that could cut off their access. Techniques used for persistence include any access, action, or configuration changes that let them maintain their foothold on systems, such as replacing or hijacking legitimate code or adding startup code. ID: TA0003 Created: 17 October 2018 Last Modified: 25
