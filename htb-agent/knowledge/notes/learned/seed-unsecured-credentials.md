# 학습 시드(심화): unsecured-credentials

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn unsecured-credentials`. P1: 머신별 라이트업 미참조.

## 개요
노출 자격(T1552): 파일·히스토리·설정·메모리의 평문/약한 자격. HTB 빈출 승격 경로.

## 핵심 기법 · 열거
- 설정파일(web.config, .env, wp-config.php)·히스토리(.bash_history)
- SSH 키·DB 연결문자열·스크립트 하드코딩·메모리
- Redis/Memcached 무인증 접근·공유 자격

## 표준 도구 · 명령
```
grep -rniE 'password|passwd|secret|api[_-]?key' /var/www /home 2>/dev/null
cat ~/.bash_history ~/.ssh/id_rsa .env 2>/dev/null
redis-cli -h <target> ; keys *            # 무인증 Redis
```

## 블루팀 탐지
민감파일 비정상 접근·설정파일 평문자격 노출·무인증 Redis 접근.

## 완화
시크릿 매니저·파일권한·히스토리 비활성·Redis 인증/바인딩·키 로테이션.

- 출처(검증): https://attack.mitre.org/techniques/T1552/
