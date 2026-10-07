# 학습 시드(심화): authentication

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn authentication`. P1: 머신별 라이트업 미참조.

## 개요
인증 결함: 약한 자격·열거·취약 2FA·재설정 로직 결함.

## 핵심 기법 · 열거
- 사용자명 열거(응답/타이밍 차이)
- 크리덴셜 스터핑·패스워드 스프레이
- 약한 재설정 토큰·2FA 우회(응답조작·코드 브루트)
- 기본자격·remember-me 토큰

## 표준 도구 · 명령
```
hydra -L users.txt -P rockyou.txt <target> http-post-form '...'
# 응답 길이/시간차로 유효 사용자 선별
```

## 블루팀 탐지
4625/4771 반복실패·분산 스터핑·동일암호 다계정(스프레이).

## 완화
레이트리밋·계정잠금·균일 오류메시지·MFA·안전한 재설정 토큰.

- 출처(검증): https://portswigger.net/web-security/authentication

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### PortSwigger Authentication
- 출처: https://portswigger.net/web-security/authentication
- 승격일: 2026-10-07
- 요약: Authentication vulnerabilities Conceptually, authentication vulnerabilities are easy to understand. However, they are usually critical because of the clear relationship between authentication and security. Authentication vulnerabilities can allow attackers to gain access to sensitive data and functionality. They also expose additional attack surface for further exploits. For this reason, it's important to learn how to identify and exploit authentication vulnerabilities, and how to bypass common
