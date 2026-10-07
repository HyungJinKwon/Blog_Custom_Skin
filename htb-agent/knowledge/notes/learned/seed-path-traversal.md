# 학습 시드(심화): path-traversal

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn path-traversal`. P1: 머신별 라이트업 미참조.

## 개요
경로순회: 파일경로 입력 조작으로 범위밖 파일 읽기/쓰기. CWE-22.

## 핵심 기법 · 열거
- ../ 시퀀스·절대경로·널바이트·인코딩(%2e%2e%2f)·이중인코딩
- 윈도우: ..\ 및 %5c, 드라이브 경로
- 접두/접미 검증 우회(....// , 중첩)
- 쓰기 가능 시 웹셸 업로드·설정 덮어쓰기

## 표준 도구 · 명령
```
curl '<url>/download?file=../../../../etc/passwd'
curl '<url>/download?file=..%2f..%2f..%2fetc%2fpasswd'
```

## 블루팀 탐지
요청 경로에 ../·인코딩 변종·민감경로(/etc/passwd, web.config). 범위밖 파일 접근.

## 완화
정규화(realpath) 후 기준디렉터리 내부 확인·허용목록·프레임워크 안전 API.

- 출처(검증): https://portswigger.net/web-security/file-path-traversal

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### PortSwigger Path Traversal
- 출처: https://portswigger.net/web-security/file-path-traversal
- 승격일: 2026-10-07
- 요약: Path traversal In this section, we explain: What path traversal is. How to carry out path traversal attacks and circumvent common obstacles. How to prevent path traversal vulnerabilities. Labs If you're familiar with the basic concepts behind path traversal and want to practice exploiting them on some realistic, deliberately vulnerable targets, you can access labs in this topic from the link below. View all path traversal labs What is path traversal? Path traversal is also known as directory tra
