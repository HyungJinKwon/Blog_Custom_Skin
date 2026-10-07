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

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### Wireshark User's Guide
- 출처: https://www.wireshark.org/docs/wsug_html_chunked/ChapterIntroduction.html
- 승격일: 2026-10-07
- 요약: Chapter 1. Introduction 1.1. What is Wireshark? Wireshark is a network packet analyzer. A network packet analyzer presents captured packet data in as much detail as possible. You could think of a network packet analyzer as a measuring device for examining what’s happening inside a network cable, just like an electrician uses a voltmeter for examining what’s happening inside an electric cable (but at a higher level, of course). In the past, such tools were either very expensive, proprietary, or b

### Display Filter Reference
- 출처: https://www.wireshark.org/docs/dfref/
- 승격일: 2026-10-07
- 요약: Display Filter Reference Wireshark's most powerful feature is its vast array of display filters (over 328000 fields in 3000 protocols as of version 4.6.9). They let you drill down to the exact traffic you want to see and are the basis of many of Wireshark's other features, such as the coloring rules. This is a reference. For general help using display filters, please see the wireshark-filter manual page or the User's Guide. Index 1234569_ABCDEFGHIJKLMNOPQRSTUVWXYZ 1 104apci: IEC 60870-5-104-Apci
