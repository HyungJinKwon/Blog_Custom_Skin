"""
Approval — 승인제 게이트 + 명령 3분할 해설
============================================

승인제(P2): 에이전트가 제안한 명령을 실행 전에 사람에게 보여주고 승인받는다.
명령은 `바이너리 / 옵션 / 파라미터` 3분할로 해설해(§5·§7), 실행 전에 "무엇을
하는 명령인지" 학습이 되게 한다. 검증(Validator)·범위(ScopeGuard) 리포트를
함께 제시한다.
"""

from __future__ import annotations

import re
import shlex

from .command_validator import ValidationReport
from .scope_guard import CommandScopeResult
from .util import binary_of

# 초보자용 한 줄 목적 설명(바이너리 → 평이한 한국어). 없는 도구는 일반 안내로 폴백.
_PURPOSE = {
    "nmap": "포트·서비스·버전을 스캔해 대상의 '열린 문'을 찾습니다",
    "rustscan": "포트를 빠르게 훑어 열린 포트를 찾습니다",
    "ffuf": "웹 경로/파라미터를 대입해 숨은 페이지를 찾습니다(퍼징)",
    "gobuster": "웹 디렉터리·파일 이름을 대입해 숨은 경로를 찾습니다",
    "feroxbuster": "웹 경로를 재귀적으로 대입해 숨은 페이지를 찾습니다",
    "dirb": "웹 디렉터리를 대입해 숨은 경로를 찾습니다",
    "wfuzz": "웹 요청 값을 대입해 숨은 입력/경로를 찾습니다",
    "nikto": "웹 서버의 알려진 취약·오설정을 점검합니다",
    "whatweb": "웹 서버·프레임워크·버전을 식별합니다",
    "curl": "웹 요청을 보내 응답(헤더·본문)을 직접 확인합니다",
    "wget": "파일/페이지를 내려받습니다",
    "smbclient": "SMB(윈도 공유)에 접속해 공유 폴더를 살핍니다",
    "smbmap": "SMB 공유와 접근 권한을 한눈에 나열합니다",
    "netexec": "SMB/WinRM 등에 자격증명을 점검·열거합니다",
    "nxc": "SMB/WinRM 등에 자격증명을 점검·열거합니다",
    "crackmapexec": "SMB/WinRM 등에 자격증명을 점검·열거합니다",
    "enum4linux": "SMB/윈도 도메인 정보를 종합 열거합니다",
    "enum4linux-ng": "SMB/윈도 도메인 정보를 종합 열거합니다",
    "ldapsearch": "LDAP(디렉터리)에서 계정·그룹 정보를 조회합니다",
    "rpcclient": "윈도 RPC로 사용자·공유 등을 조회합니다",
    "dig": "DNS 레코드를 조회합니다",
    "snmpwalk": "SNMP로 장비 설정·정보를 열거합니다",
    "showmount": "NFS 공유 목록을 조회합니다",
    "redis-cli": "Redis 서버에 접속해 상태·데이터를 확인합니다",
    "mysql": "MySQL/MariaDB 에 접속합니다",
    "psql": "PostgreSQL 에 접속합니다",
    "ssh": "SSH 로 원격 셸에 접속합니다",
    "ftp": "FTP 서버에 접속합니다",
    "hydra": "로그인에 자격증명을 대입해봅니다(권한 확인 대상 한정)",
    "wpscan": "WordPress 의 플러그인·사용자·취약점을 점검합니다",
}


def explain_purpose(command: str) -> str:
    """명령이 '무엇을 하려는지' 한 줄 평이 설명(초보자용). 미등록 도구는 일반 안내."""
    b = binary_of(command, strip_path=True)
    return _PURPOSE.get(b, f"'{b}' 도구를 실행합니다 — 옵션·파라미터는 아래 3분할 해설 참고")


# 동적·원격 코드 실행(검토 대상)에 대한 '더 안전한 2단계 대안' — 초보자가 바로 고를 수 있게.
def safer_alternative(command: str) -> str | None:
    """검토 대상(파이프→셸, IEX 등)에 대해 '먼저 내용 확인 → 그 다음 실행'형 대안을 제시.
    대상이 불명확하면 일반 원칙만 돌려준다(명령을 지어내지 않음)."""
    c = command
    # 파이프로 받은 내용을 바로 셸/인터프리터에 흘리는 형태
    if re.search(r"\|\s*(?:sudo\s+)?(?:/\S*/)?(?:(?:ba|z|da|k|c|tc|fi)?sh|python[0-9.]*|perl|ruby|php|node)\b", c):
        left = c.split("|", 1)[0].strip()
        return (f"받은 내용을 바로 실행하지 말고 2단계로: ① `{left}` 로 먼저 내려받아 눈으로 확인 "
                "② 안전하면 그때 실행. (한 줄로 바로 실행하면 내용 확인 없이 임의 코드가 돕니다)")
    if re.search(r"(?i)\b(?:iex|invoke-expression)\b", c):
        return ("IEX(바로 실행) 대신: ① `Invoke-WebRequest -OutFile a.ps1 <URL>` 로 저장 "
                "② 내용 확인 후 `.\\a.ps1` 로 실행.")
    if re.search(r"(?i)\bdownloadstring\b", c):
        return "DownloadString(받자마자 실행) 대신 DownloadFile 로 저장 후 내용을 확인하고 실행하세요."
    if re.search(r"\$\((?!\()|`[^`]+`", c):
        return "명령 치환(`$(...)`/백틱)은 실행 시점에 내용이 정해집니다 — 치환될 명령을 먼저 따로 실행해 확인하세요."
    return None

# 값을 받는 옵션(이 목록에 한해서만 다음 토큰을 '값'으로 페어링 — 부울 플래그 뒤
# 위치 인자(예: 타겟 IP)를 값으로 오인하지 않도록 보수적으로 제한).
_VALUE_OPTS = {
    "-u", "-w", "-p", "-P", "-l", "-L", "-H", "-d", "-X", "-o", "-oX", "-oA",
    "-oN", "-oG", "-mc", "-fs", "-ms", "-fc", "-t", "-b", "-s", "-D", "-i",
    "-U", "-c", "-e", "-x", "--script", "--user", "--password", "--dc-ip",
    "--url", "-request", "-usersfile", "-k",
}


def explain_command(command: str) -> str:
    """명령을 바이너리/옵션/파라미터로 3분할 해설."""
    try:
        toks = shlex.split(command)
    except ValueError:
        toks = command.split()
    if not toks:
        return "(빈 명령)"
    # 선행 환경변수 할당은 별도 표기
    env, i = [], 0
    while i < len(toks) and "=" in toks[i].split("/", 1)[0] and not toks[i].startswith("-"):
        env.append(toks[i]); i += 1
    binary = toks[i] if i < len(toks) else ""
    rest = toks[i + 1:]
    # 값 받는 옵션은 다음 토큰을 값으로 페어링(화이트리스트 한정, 보수적)
    options: list[str] = []
    params: list[str] = []
    j = 0
    while j < len(rest):
        t = rest[j]
        if t.startswith("-"):
            if "=" not in t and t in _VALUE_OPTS and j + 1 < len(rest) \
                    and not rest[j + 1].startswith("-"):
                options.append(f"{t} {rest[j + 1]}")
                j += 2
                continue
            options.append(t)
        else:
            params.append(t)
        j += 1
    # 플레인 텍스트 유지(라이트업 Markdown·테스트 호환). 색은 render_proposal 에서.
    lines = ["[명령 3분할 해설]"]
    if env:
        lines.append(f"  환경변수 : {' '.join(env)}")
    lines.append(f"  바이너리 : {binary}")
    lines.append(f"  옵션     : {' '.join(options) or '(없음)'}")
    lines.append(f"  파라미터 : {' '.join(params) or '(없음)'}")
    return "\n".join(lines)


def render_proposal(command: str, vrep: ValidationReport,
                    sres: CommandScopeResult) -> str:
    """승인 요청 화면 텍스트(블루/네이비 박스)."""
    from . import ui
    body = [
        ui.accent2("$ ") + ui.bold(command),
        ui.dim("─" * max(10, min(70, ui.display_width(command) + 2))),
        ui.kv("목적", explain_purpose(command), 8),
        *explain_command(command).splitlines(),
        "",
        ui.kv("검증", ui.mark_ok("통과") if vrep.ok else ui.mark_err("실패"), 8),
        *[ui.bullet(str(i), " ", "dim") for i in vrep.issues],
        ui.kv("범위", ui.mark_ok("자동허용") if sres.auto_allowed
              else ui.mark_warn("추가확인 필요"), 8),
        *([ui.bullet(", ".join(sres.needs_confirmation), "▲", "warn")]
          if sres.needs_confirmation else []),
        *([ui.kv("실행위험", ui.mark_warn("사람 검토 필요"), 8)] if vrep.review else []),
        *([ui.kv("대안", ui.info(alt), 8)]
          if vrep.review and (alt := safer_alternative(command)) else []),
        *([ui.kv("범위 밖", ui.dim("내 VPN IP 라면 --attacker-ip 로 등록, 아니면 건너뛰세요(N)"), 8)]
          if not sres.auto_allowed else []),
    ]
    style = "accent" if (vrep.ok and sres.auto_allowed and not vrep.review) else "warn"
    return ui.panel("실행 제안 (승인 대기)", body, style=style)


def interactive_approver(command: str, vrep: ValidationReport,
                         sres: CommandScopeResult) -> bool:
    """
    대화형 승인(Kali 터미널). 검증 실패면 자동 거부. 범위밖이면 명시적 재확인.
    반환 True=실행 승인.
    """
    from . import ui
    print(render_proposal(command, vrep, sres))
    if not vrep.ok:
        print(ui.mark_err("검증 실패 — 실행 거부합니다."))
        return False
    prompt = ui.accent2("실행할까요?") + ui.dim(" [y=실행 / 엔터=건너뛰기] ")
    risks = (["범위 밖 대상"] if not sres.auto_allowed else []) \
        + (["동적·원격 코드 실행"] if vrep.review else [])
    if risks:
        prompt = (ui.warn(f"▲ {' + '.join(risks)} 포함 — 위 '대안'을 먼저 보고 결정하세요. 실행?")
                  + ui.dim(" [y=실행 / 엔터=건너뛰기(수동 제안으로 보관)] "))
    try:
        ans = input(prompt).strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes")


def smart_approver(command: str, vrep: ValidationReport,
                   sres: CommandScopeResult) -> bool:
    """
    스마트 자동 승인(기본 모드). '나머지는 다 자동, 엄격한 권한만 확인':
      - 검증 실패(파괴명령 포함) → 자동 거부(무프롬프트)
      - 범위내 + 검증통과         → 자동 실행(무프롬프트)
      - 범위 밖(권한 경계)        → 사람에게 1회 확인(interactive)
      - 동적·원격 코드 실행(검토) → 사람에게 1회 확인(interactive)
    """
    from . import ui
    if not vrep.ok:
        print(ui.mark_err("검증 실패 — 자동 거부: ") + ui.dim(command))
        for i in vrep.issues:
            print(ui.dim(f"   {i}"))
        return False
    if sres.auto_allowed and not vrep.review:
        return True
    # 범위 밖 = 엄격한 권한 경계 / 실행내용 불명 = 검토 필요 → 명시 확인
    return interactive_approver(command, vrep, sres)
