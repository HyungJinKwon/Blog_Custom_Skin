# HTB Starting Point Tier 0 — 방법론 (사용자 제공 라이트업 학습)

Tier 0 공통 벡터: **약한/빈/익명/기본 자격** 오구성. 서비스 식별 → 전용 열거 →
비인증 접근 → flag 획득. 머신별 요약:

- Meow(23 telnet/Linux): 빈 비번 root 로그인 → cat flag.txt
- Fawn(21 ftp/Linux): 익명 로그인 → get flag.txt
- Dancing(445 smb/Windows): 익명 공유 WorkShares → get flag.txt
- Redeemer(6379 redis/Linux): 비인증 keys * → get <key>
- Explosion(3389 rdp/Windows): Administrator 빈 비번 → 데스크톱 flag
- Preignition(80 nginx/Linux): gobuster → /admin.php → admin/admin
- Mongod(27017 mongodb/Linux): 비인증 → db.flag.find()
- Synced(873 rsync/Linux): 익명 모듈 public → rsync 다운로드

핵심 교훈: 포트 하나만 열려도 그 서비스의 비인증/기본자격을 먼저 점검.
flag 파일명은 flag.txt(SP) / user.txt·root.txt(정규 머신).
