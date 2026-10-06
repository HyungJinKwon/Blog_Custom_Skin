# 학습 시드(심화): ftp

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn ftp`. P1: 머신별 라이트업 미참조.

## 개요
FTP(21): 평문 파일전송. 익명·쓰기가능·자격 스니핑.

## 핵심 기법 · 열거
- 익명 로그인(anonymous:anonymous)·디렉터리 열거
- 쓰기가능 시 웹셸/백도어 업로드
- 평문 자격·바운스 공격·vsftpd 2.3.4 백도어

## 표준 도구 · 명령
```
ftp <target>   # anonymous / 빈 암호
nxc ftp <target> -u anonymous -p ''
wget -r ftp://anonymous:@<target>/
```

## 블루팀 탐지
평문 자격 노출·익명 접근·비정상 전송.

## 완화
FTPS/SFTP 대체·익명 비활성·강한 자격·쓰기권한 최소화.

- 출처(검증): https://datatracker.ietf.org/doc/html/rfc959
