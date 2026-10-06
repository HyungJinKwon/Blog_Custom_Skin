# 학습 시드(심화): ssh

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn ssh`. P1: 머신별 라이트업 미참조.

## 개요
SSH(22): 보안 원격접속. 약한 자격·키 오관리·피벗.

## 핵심 기법 · 열거
- 자격 브루트·노출 개인키·약한 암호
- 키 기반 로그인·에이전트/포트 포워딩 피벗
- sudo/셸 탈출로 권한상승 연계

## 표준 도구 · 명령
```
ssh user@<target> ; ssh -i id_rsa user@<target>
hydra -L users.txt -P rockyou.txt ssh://<target>
chmod 600 id_rsa ; ssh2john id_rsa > h ; john h   # 키 암호 크랙
```

## 블루팀 탐지
반복 인증실패·비정상 키 로그인·터널링·비정상 시간 접속.

## 완화
키 인증·암호로그인 비활성·fail2ban·MFA·AllowUsers.

- 출처(검증): https://datatracker.ietf.org/doc/html/rfc4253
