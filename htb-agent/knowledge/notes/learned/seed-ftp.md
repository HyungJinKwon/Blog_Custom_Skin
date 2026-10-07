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

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### Wireshark FTP
- 출처: https://wiki.wireshark.org/FTP
- 승격일: 2026-10-07
- 요약: File Transfer Protocol (FTP) As the name implies, FTP is used to transfer files. It is a standard communication protocol built on a client-server model and relies on two separate communication channels: a control channel for sending commands and responses, and a data channel for actually transmitting the file content. Security Warning: FTP uses plain text passwords, so take care when using it. History FTP is one of the oldest internet protocols, initially developed and published as RFC114 in 197

### RFC 959 FTP
- 출처: https://datatracker.ietf.org/doc/html/rfc959
- 승격일: 2026-10-07
- 요약: This memo is the official specification of the File Transfer Protocol (FTP). Distribution of this memo is unlimited. The following new optional commands are included in this edition of the specification: CDUP (Change to Parent Directory), SMNT (Structure Mount), STOU (Store Unique), RMD (Remove Directory), MKD (Make Directory), PWD (Print Directory), and SYST (System). Note that this specification is compatible with the previous edition. 1. INTRODUCTION The objectives of FTP are 1) to promote sh
