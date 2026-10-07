# 학습 시드(심화): jwt

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn jwt`. P1: 머신별 라이트업 미참조.

## 개요
JWT 공격: 토큰 서명/검증 결함으로 인증우회·권한상승.

## 핵심 기법 · 열거
- alg:none 수용(서명 제거)
- 약한 HMAC 비밀키 크래킹(hashcat)
- RS256→HS256 혼동(공개키를 HMAC 키로)
- kid 주입(경로순회/SQLi)·jku/x5u 외부키 신뢰
- claim 조작(role:admin)

## 표준 도구 · 명령
```
hashcat -m 16500 jwt.txt rockyou.txt          # HMAC 크랙
python3 jwt_tool.py <token> -X a              # alg:none
python3 jwt_tool.py <token> -X k -pk pub.pem  # RS→HS 혼동
```

## 블루팀 탐지
서버 로그의 alg 변경·서명검증 실패 급증·동일 사용자 다권한 토큰.

## 완화
강한 키·alg 화이트리스트(고정)·kid/jku 검증·만료 짧게·서명 필수 검증.

- 출처(검증): https://portswigger.net/web-security/jwt

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### PortSwigger JWT
- 출처: https://portswigger.net/web-security/jwt
- 승격일: 2026-10-07
- 요약: JWT attacks In this section, we'll look at how design issues and flawed handling of JSON web tokens (JWTs) can leave websites vulnerable to a variety of high-severity attacks. As JWTs are most commonly used in authentication, session management, and access control mechanisms, these vulnerabilities can potentially compromise the entire website and its users. Don't worry if you're not familiar with JWTs and how they work - we'll cover all of the relevant details as we go. We've also provided a num
