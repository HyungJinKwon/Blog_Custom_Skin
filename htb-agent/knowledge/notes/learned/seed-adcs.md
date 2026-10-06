# 학습 시드: adcs (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn adcs` 로 갱신.

AD CS 인증서 서비스 악용(ESC1~): 취약 템플릿(클라이언트인증 EKU + ENROLLEE_SUPPLIES_SUBJECT)이면 임의 UPN(관리자)로 인증서 발급→PKINIT 로 TGT/NTLM 획득. ESC8=NTLM 릴레이 to 웹등록(HTTP). 도구 certipy(find -vulnerable / req / auth). 완화: 템플릿 권한·수동 승인·EDITF_ATTRIBUTESUBJECTALTNAME2 제거.

- 출처(검증): https://attack.mitre.org/techniques/T1649/
