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

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### Nmap Reference Guide
- 출처: https://nmap.org/book/man.html
- 승격일: 2026-10-07
- 요약: Chapter 15. Nmap Reference Guide Name nmap — Network exploration tool and security / port scanner Synopsis nmap [ <Scan Type> ...] [ <Options> ] { <target specification> } Description Note This document describes the very latest version of Nmap available from https://nmap.org/download.html or https://nmap.org/dist/?C=M&O=D. Please ensure you are using the latest version before reporting that a feature doesn't work as described. Nmap (“Network Mapper”) is an open source tool for network explorati

### NSE 문서
- 출처: https://nmap.org/book/nse.html
- 승격일: 2026-10-07
- 요약: Chapter 9. Nmap Scripting Engine Introduction The Nmap Scripting Engine (NSE) is one of Nmap's most powerful and flexible features. It allows users to write (and share) simple scripts to automate a wide variety of networking tasks. Those scripts are then executed in parallel with the speed and efficiency you expect from Nmap. Users can rely on the growing and diverse set of scripts distributed with Nmap, or write their own to meet custom needs. We designed NSE to be versatile, with the following
