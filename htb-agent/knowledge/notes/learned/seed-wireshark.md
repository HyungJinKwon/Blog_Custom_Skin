# 학습 시드(심화): wireshark

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn wireshark`. P1: 머신별 라이트업 미참조.

## 개요
Wireshark: 패킷 분석. 평문 자격·프로토콜 흐름·침해 분석.

## 핵심 기법 · 열거
- 디스플레이 필터로 프로토콜/호스트 분리
- 평문 자격(FTP/HTTP/Telnet) 추출·TCP 스트림 추적
- tshark 로 CLI 자동화

## 표준 도구 · 명령
```
tshark -r cap.pcap -Y 'http.request' -T fields -e http.host -e http.request.uri
필터: tcp.port==21 || ftp ; http.authorization ; tcp contains "pass"
tshark -r cap.pcap -z follow,tcp,ascii,0
```

## 블루팀 탐지
(분석 도구). 블루팀 관점: 평문 자격·비정상 흐름·C2 패턴 식별에 사용.

## 완화
(도구). 평문 프로토콜 제거·암호화가 근본 완화.

- 출처(검증): https://www.wireshark.org/docs/wsug_html_chunked/
