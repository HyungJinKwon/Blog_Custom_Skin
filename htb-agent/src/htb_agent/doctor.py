"""
Doctor — 환경 자가진단 (완전 초보자용)
=======================================

`assassin --doctor` 로 스캔 없이 '지금 쓸 준비가 됐는지'를 한눈에 점검한다.
각 항목을 ✔/▲/✘ 로 보여주고, 안 된 항목마다 '다음에 뭘 하면 되는지'를 바로
알려준다(복붙 가능한 명령). 네트워크·대상 없이 동작한다.

점검: 시스템(파이썬/OS/VPN) · 핵심 도구 · LLM 백엔드 · 종합 다음 단계.
"""
from __future__ import annotations

import platform
import sys

from . import __version__
from . import ui
from .environment import detect_vpn_ips, _is_kali
from .tools import registry

# 초보자가 가장 먼저 필요한 '핵심' 도구(전체 63개 중). 나머지는 install_tools.sh.
ESSENTIAL_TOOLS = ["nmap", "curl", "ffuf", "gobuster", "netexec",
                   "smbclient", "sshpass", "hydra"]


def _check_llm() -> list[tuple[str, bool, str, str]]:
    """(이름, OK?, 상태, 설치힌트) 목록. import 실패도 안전 처리."""
    rows: list[tuple[str, bool, str, str]] = []
    try:
        from .llm.claude_provider import ClaudeProvider
        ok, reason = ClaudeProvider().available()
        rows.append(("Claude(API)", ok, reason,
                     "pip install anthropic && export ANTHROPIC_API_KEY=sk-..."))
    except Exception as e:                       # noqa: BLE001 - 진단은 중단 금지
        rows.append(("Claude(API)", False, f"로드 실패: {e}",
                     "pip install anthropic"))
    try:
        from .llm.ollama_provider import OllamaProvider
        prov = OllamaProvider()
        ok, reason = prov.available()
        rows.append(("Ollama(로컬)", ok, reason,
                     "ollama 설치 후 'ollama serve' + 'ollama pull llama3.1:8b' "
                     f"(호스트 {prov.host})"))
    except Exception as e:                       # noqa: BLE001
        rows.append(("Ollama(로컬)", False, f"로드 실패: {e}",
                     "https://ollama.com 설치 후 'ollama pull llama3.1:8b'"))
    return rows


def run_doctor() -> tuple[str, bool]:
    """진단 텍스트와 '치명적 문제 없음' 여부를 반환."""
    blocking = False
    out: list[str] = [ui.banner("환경 자가진단 (완전 초보자용)")]

    # 1) 시스템
    sys_lines = []
    pyok = sys.version_info >= (3, 10)
    pv = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    sys_lines.append((ui.mark_ok if pyok else ui.mark_err)(f"Python {pv}")
                     + ("" if pyok else ui.dim("  → 3.10 이상 필요")))
    if not pyok:
        blocking = True
    is_linux = platform.system() == "Linux"
    if is_linux:
        sys_lines.append(ui.mark_ok("Linux" + (" (Kali)" if _is_kali()
                         else " — Kali 아님(일부 apt 패키지 상이 가능)")))
    else:
        sys_lines.append(ui.mark_warn(f"{platform.system()} — 실제 공격/VPN 은 Kali/Linux 권장"))
    vpn = detect_vpn_ips()
    if vpn:
        sys_lines.append(ui.mark_ok(f"VPN(tun/tap) IP: {', '.join(vpn)}"))
    else:
        sys_lines.append(ui.mark_warn("VPN(tun/tap) 미탐지")
                         + ui.dim("  → HTB는 'sudo openvpn 파일.ovpn' (CTF/로컬은 불필요)"))
    out.append(ui.panel("1. 시스템", sys_lines, style="navy"))

    # 2) 핵심 도구
    avail = registry.check_available()
    tool_lines = []
    missing_ess = []
    for k in ESSENTIAL_TOOLS:
        t = registry.TOOLS_BY_KEY.get(k)
        if t is None:
            continue
        path = avail.get(k)
        if path:
            tool_lines.append(ui.mark_ok(f"{k:10}") + ui.dim(path))
        else:
            missing_ess.append(k)
            tool_lines.append(ui.mark_err(f"{k:10}") + ui.dim("미설치 → " + t.install_hint()))
    total = len(registry.TOOLS)
    installed = sum(1 for v in avail.values() if v)
    tool_lines.append(ui.dim(f"전체 도구 {installed}/{total} 설치됨"))
    if missing_ess:
        tool_lines.append(ui.accent2("일괄 설치: ") + ui.bold("sudo ./scripts/install_tools.sh"))
    out.append(ui.panel("2. 핵심 도구", tool_lines, style="navy"))

    # 3) LLM 백엔드(선택)
    llm_lines = []
    any_llm = False
    for name, ok, reason, hint in _check_llm():
        short = reason if len(reason) <= 60 else reason[:57] + "..."
        if ok:
            any_llm = True
            llm_lines.append(ui.mark_ok(f"{name:14}") + ui.dim(short))
        else:
            llm_lines.append(ui.mark_warn(f"{name:14}") + ui.dim(short))
            llm_lines.append(ui.dim(f"   → {hint}"))
    if any_llm:
        llm_lines.append(ui.ok("LLM 사용 가능") + ui.dim("  (--llm hybrid/claude/ollama)"))
    else:
        llm_lines.append(ui.info("LLM 없이도 규칙기반으로 완전 동작")
                         + ui.dim("  (--llm none, 기본값)"))
    out.append(ui.panel("3. LLM 두뇌 (선택)", llm_lines, style="navy"))

    # 4) 종합 · 다음 단계
    nxt = []
    if blocking:
        nxt.append(ui.mark_err("치명적: Python 3.10+ 로 업그레이드 후 다시 시도"))
    if missing_ess:
        nxt.append(ui.mark_run("도구 설치: ") + "sudo ./scripts/install_tools.sh")
    if not vpn:
        nxt.append(ui.mark_run("HTB면 VPN 연결: ") + "sudo openvpn <파일>.ovpn")
    nxt.append(ui.mark_run("첫 실행(HTB): ") + "assassin 10.129.x.x")
    nxt.append(ui.mark_run("첫 실행(CTF): ") + "assassin chall.site:1337 --platform ctf")
    nxt.append(ui.dim("자세한 운영/문제해결: docs/OPERATIONS.md"))
    out.append(ui.panel("4. 다음 단계", nxt,
                        style="accent" if not blocking else "warn"))

    out.append(ui.dim(f"ASSASSIN {__version__} · 이 진단은 네트워크·대상 없이 동작합니다."))
    return "\n".join(out), not blocking
