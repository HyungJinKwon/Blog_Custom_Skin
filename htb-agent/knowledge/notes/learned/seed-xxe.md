# 학습 시드: xxe (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn xxe` 로 갱신.

XML 외부개체 주입: XML 파서가 외부개체 처리 시 파일읽기(file://)·SSRF·OOB 반출·DoS(빌리언래프). 블라인드는 OOB DTD 로. CWE-611. 블루팀: XML 입력의 DOCTYPE/ENTITY·file:// 참조·OOB 콜백 탐지. 완화: 외부개체·DTD 비활성(파서 강화).

- 출처(검증): https://portswigger.net/web-security/xxe
