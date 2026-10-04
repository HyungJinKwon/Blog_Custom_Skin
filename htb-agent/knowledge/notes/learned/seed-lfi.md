# 학습 시드: lfi (큐레이션 요약)

> 사전 심은 큐레이션 개념 요약(확립된 보안 지식). 라이브 수집 아님 — 권위 출처에서 검증 가능. 최신 본문은 `assassin --learn lfi` 로 갱신.

경로 조작(../)으로 서버 로컬 파일 포함/읽기. php wrapper·log poisoning→RCE. 완화: 경로 정규화·화이트리스트, allow_url_include off.

- 출처(검증): https://owasp.org/www-community/attacks/Path_Traversal
