# CTF / Dreamhack Jeopardy 카테고리 방법론 (사용자 제공 학습)

HTB boot2root 와 달리 Jeopardy 는 카테고리별 단일 플래그(flag{...}/DH{...}). 범위는
대회가 명시한 챌린지 인스턴스(host:port/URL)만. 승인제·외부 라이트업 미참조 동일 적용.

## web
- 응답헤더/쿠키/robots.txt/sitemap, View-Source, HTML 주석, JS 내 엔드포인트·키
- gobuster/ffuf 로 숨은 경로, /.git(git-dumper)·*.bak·*.swp 소스복원
- 취약점: SQLi·XSS·SSTI·LFI/RFI·SSRF·IDOR·인증우회(타입저글링)·역직렬화·업로드 RCE·JWT 위조
- 제공 소스가 있으면 먼저 읽고 취약 라우트 식별 → 로컬 재현

## pwn (포너블)
- checksec(NX/PIE/Canary/RELRO) → file/strings → Ghidra/IDA 디컴파일
- BOF·포맷스트링·UAF·OOB → pwntools(remote(host,port)). libc 주면 ret2libc/one_gadget
- ROP(ropper/ROPgadget), GOT overwrite, 쉘 획득 후 cat flag

## rev (리버싱)
- file/strings/ltrace/strace, Ghidra/IDA/angr. 안티디버그 우회, 키 검증 로직 복원
- .NET=dnSpy/ILSpy, Java=jadx, 패킹=UPX 언팩, 심볼릭 실행(angr)로 입력 역산

## crypto
- RSA(약한 e/공통모듈러스/Wiener/Fermat, factordb), AES(ECB 패턴·패딩오라클·비트플립)
- XOR(반복키 crib-drag), 해시(길이확장 hashpump), 고전암호(CyberChef)
- sagemath/pycryptodome 로 수학적 공격

## forensic
- file/binwalk/foremost(카빙), exiftool(메타), steghide/zsteg/stegsolve(스테가노)
- pcap=Wireshark/tshark(스트림·크리덴셜), 메모리=volatility, 디스크=autopsy
- strings | grep -i flag, 숨김파일/슬랙공간

## misc
- 인코딩(base64/32/58/hex, CyberChef magic), QR/바코드, esoteric 언어
- OSINT(사용자 선호 연구주제), 로그분석, 자동화 스크립트

핵심: 모든 카테고리에서 `strings | grep -iE 'flag|DH\{|CTF\{'` 는 빠른 1차 점검.
플래그 접두는 대회가 지정(DH{}, flag{} 등) → --flag-prefix 로 추가 가능.
