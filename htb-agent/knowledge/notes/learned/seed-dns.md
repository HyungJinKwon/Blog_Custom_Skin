# 학습 시드(심화): dns

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn dns`. P1: 머신별 라이트업 미참조.

## 개요
DNS(53): 이름해석. 존 전송·서브도메인 열거·vhost 발견.

## 핵심 기법 · 열거
- AXFR 존 전송 시도
- 서브도메인 브루트·역방향 조회
- HTB: /etc/hosts 에 도메인 추가 필요 빈번

## 표준 도구 · 명령
```
dig axfr @<target> <domain>                   # 존 전송
dnsenum <domain> ; gobuster dns -d <domain> -w subs.txt
echo '<ip> <domain>' | sudo tee -a /etc/hosts
```

## 블루팀 탐지
AXFR 시도·대량 서브도메인 질의·비정상 역방향 조회.

## 완화
AXFR 제한(신뢰 secondary)·존 분리·질의 레이트리밋.

- 출처(검증): https://datatracker.ietf.org/doc/html/rfc1035
