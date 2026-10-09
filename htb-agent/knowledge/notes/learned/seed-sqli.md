# 학습 시드(심화): sqli

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn sqli`. P1: 머신별 라이트업 미참조.

## 개요
SQL 주입: 사용자 입력이 SQL 질의에 그대로 합쳐져 인증우회·데이터유출·RCE 로 이어진다. CWE-89.

## 핵심 기법 · 열거
- In-band(Union/Error): 즉시 결과 반환. UNION SELECT 로 컬럼 수·데이터 추출
- Blind Boolean: 참/거짓 응답차로 1비트씩 추출 (AND 1=1 vs 1=2)
- Blind Time: 응답지연으로 추출 (SLEEP(5)/pg_sleep(5)/WAITFOR DELAY)
- Out-of-band: DNS/HTTP 콜백으로 추출(제약 환경)
- 스택질의·2차 주입·WAF 우회(주석/인코딩/대소문자)
- DBMS 식별 후 RCE: MSSQL xp_cmdshell, MySQL INTO OUTFILE 웹셸, PostgreSQL COPY/프로그램

## 표준 도구 · 명령
```
sqlmap -u '<url>?id=1' --batch --dbs       # 자동 탐지·열거
sqlmap -u '<url>' --data 'u=a&p=b' --dump --threads 4
sqlmap -r req.txt --level 5 --risk 3 --tamper=space2comment
' UNION SELECT NULL,version(),database()-- -   # 수동 폴리글랏
' OR SLEEP(5)-- -                              # 시간기반 확인
```

## 블루팀 탐지
SIEM: 입력에 UNION/SLEEP/INFORMATION_SCHEMA·단일따옴표 급증. WAF/IDS: libinjection·Snort SQLi 룰. DB감사: 비정상 UNION·스키마 질의.

## 완화
파라미터화 질의(Prepared Statement)·ORM·최소권한 DB계정·입력 허용목록·WAF. xp_cmdshell/INTO OUTFILE 비활성.

- 출처(검증): https://community.owasp.org/attacks/SQL_Injection

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### OWASP SQL Injection
- 출처: https://community.owasp.org/attacks/SQL_Injection
- 승격일: 2026-10-07
- 요약: SQL Injection Overview A SQL injection attack consists of insertion or “injection” of a SQL query via the input data from the client to the application. A successful SQL injection exploit can read sensitive data from the database, modify database data (Insert/Update/Delete), execute administration operations on the database (such as shutdown the DBMS), recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. SQL injection attac

### PortSwigger SQL Injection
- 출처: https://portswigger.net/web-security/sql-injection
- 승격일: 2026-10-07
- 요약: SQL injection In this section, we explain: What SQL injection (SQLi) is. How to find and exploit different types of SQLi vulnerabilities. How to prevent SQLi. Labs If you're familiar with the basic concepts behind SQLi vulnerabilities and want to practice exploiting them on some realistic, deliberately vulnerable targets, you can access labs in this topic from the link below. View all SQL injection labs What is SQL injection (SQLi)? SQL injection (SQLi) is a web security vulnerability that allow
