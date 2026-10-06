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

- 출처(검증): https://owasp.org/www-community/attacks/SQL_Injection
