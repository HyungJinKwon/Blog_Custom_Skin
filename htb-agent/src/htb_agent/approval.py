"""
Approval — 승인제 게이트 + 명령 3분할 해설
============================================

승인제(P2): 에이전트가 제안한 명령을 실행 전에 사람에게 보여주고 승인받는다.
명령은 `바이너리 / 옵션 / 파라미터` 3분할로 해설해(§5·§7), 실행 전에 "무엇을
하는 명령인지" 학습이 되게 한다. 검증(Validator)·범위(ScopeGuard) 리포트를
함께 제시한다.
"""

from __future__ import annotations

import shlex

from .command_validator import ValidationReport
from .scope_guard import CommandScopeResult

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
        *explain_command(command).splitlines(),
        "",
        ui.kv("검증", ui.mark_ok("통과") if vrep.ok else ui.mark_err("실패"), 8),
        *[ui.bullet(str(i), " ", "dim") for i in vrep.issues],
        ui.kv("범위", ui.mark_ok("자동허용") if sres.auto_allowed
              else ui.mark_warn("추가확인 필요"), 8),
        *([ui.bullet(", ".join(sres.needs_confirmation), "▲", "warn")]
          if sres.needs_confirmation else []),
        *([ui.kv("실행위험", ui.mark_warn("사람 검토 필요"), 8)] if vrep.review else []),
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
    prompt = ui.accent2("실행할까요?") + ui.dim(" [y/N] ")
    risks = (["범위 밖 대상"] if not sres.auto_allowed else []) \
        + (["동적·원격 코드 실행"] if vrep.review else [])
    if risks:
        prompt = ui.warn(f"▲ {' + '.join(risks)} 포함 — 내용 확인 후 실행?") + ui.dim(" [y/N] ")
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
