# 권한상승 · 공개 CVE 방법론 (일반 지식, 특정 머신 라이트업 아님)

> 모든 익스플로잇 실행은 승인·판단이 필요하며, 에이전트는 '탐지 + 수동 제안'까지만 한다(P1·승인제).

## 원격 서비스 CVE (배너/버전 탐지 가능)
`knowledge/vulns/common-services.json` 에 공개 사실 기반으로 수록. nmap `-sC -sV` 배너의
서비스명+버전으로 매칭된다. 매칭 시 CVE/CWE/심각도와 `searchsploit` 제안을 표기하고,
Enricher 가 NVD/GitHub PoC 레퍼런스를 자동 보강한다.

- Exim 4.87~4.91 → CVE-2019-10149 (root RCE)
- Webmin 1.890~1.920 → CVE-2019-15107 (비인증 RCE)
- Tomcat AJP(8009) → CVE-2020-1938 Ghostcat (파일읽기/포함)
- Grafana 8.0~8.3.0 → CVE-2021-43798 (경로우회 파일읽기)
- Jenkins ≤2.441 → CVE-2024-23897 (CLI 임의파일 읽기)
- Confluence → CVE-2022-26134 (OGNL RCE)
- Spring → CVE-2022-22965 Spring4Shell, Struts2 → CVE-2017-5638
- Drupal → CVE-2018-7600 Drupalgeddon2, PHP-CGI → CVE-2012-1823

## Linux 권한상승 순서
1. 열거: `id`, `sudo -l`, SUID(`find / -perm -4000`), capabilities(`getcap -r /`) → GTFOBins 대조
2. 커널: `uname -r` → Dirty Pipe(CVE-2022-0847, 5.8~5.16.x) / Dirty COW(CVE-2016-5195, <4.8.3)
3. 로컬 SUID: PwnKit(CVE-2021-4034, pkexec) / Sudo Baron Samedit(CVE-2021-3156, <1.9.5p2)
4. 설정약점: cron 쓰기/와일드카드, 쓰기가능 /etc/passwd, 평문 자격(history/config)

## Windows/AD 권한상승·측면이동 순서
1. 토큰: `whoami /priv` → SeImpersonate 시 PotatoFamily(PrintSpoofer/GodPotato)
2. Kerberos: AS-REP Roasting(GetNPUsers, hashcat -m 18200) / Kerberoasting(GetUserSPNs, -m 13100)
3. 서비스 CVE: Zerologon(CVE-2020-1472) / PrintNightmare(CVE-2021-34527) — DC 손상 위험, 수동
4. 측면이동: Pass-the-Hash(netexec -H) / DCSync(secretsdump --ntds) → Golden Ticket

출처: NVD(services.nvd.nist.gov), MITRE ATT&CK, 각 벤더 보안권고.
