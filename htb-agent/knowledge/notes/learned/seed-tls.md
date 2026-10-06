# 학습 시드(심화): tls

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn tls`. P1: 머신별 라이트업 미참조.

## 개요
TLS/SSL: 전송 암호화. 설정/인증서에서 정보·취약점.

## 핵심 기법 · 열거
- 인증서 SAN 에서 도메인/호스트 발견
- 약한 암호군·구버전·취약점(Heartbleed 등)

## 표준 도구 · 명령
```
openssl s_client -connect <target>:443 </dev/null 2>/dev/null|openssl x509 -noout -text|grep -A1 'Subject Alternative'
sslscan <target>:443 ; nmap --script ssl-enum-ciphers -p443 <target>
```

## 블루팀 탐지
약한 프로토콜/암호 협상·만료/자가서명 인증서·비정상 핸드셰이크.

## 완화
TLS1.2+·강한 암호군·HSTS·유효 인증서·취약 버전 비활성.

- 출처(검증): https://datatracker.ietf.org/doc/html/rfc8446
