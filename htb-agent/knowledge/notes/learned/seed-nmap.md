# 학습 시드(심화): nmap

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn nmap`. P1: 머신별 라이트업 미참조.

## 개요
Nmap: 포트/서비스/OS 탐지 + NSE. 정찰의 표준 1단계.

## 핵심 기법 · 열거
- TCP SYN(-sS)/connect(-sT)·UDP(-sU)·버전(-sV)·OS(-O)
- NSE 스크립트(-sC 기본, --script vuln/범주)
- 전체포트(-p-)·속도 타이밍(-T4)·핑생략(-Pn)

## 표준 도구 · 명령
```
nmap -sC -sV -oA scan <target>                 # 표준 첫 스캔
nmap -p- --min-rate 2000 -oA all <target>      # 전체포트 고속
nmap -sV --script vuln -p <ports> <target>     # 취약 스크립트
nmap -sU --top-ports 50 <target>               # UDP
```

## 블루팀 탐지
수평 포트스캔(단일출발→다수포트)·SYN 급증·NSE 특유 프로브.

## 완화
IDS/IPS·불필요 서비스 제거·레이트리밋·분할.

- 출처(검증): https://nmap.org/book/man.html
