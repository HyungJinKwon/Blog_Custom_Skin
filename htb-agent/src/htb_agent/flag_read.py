"""플래그 읽기를 '발판 셸 세션'으로 (E단계) — 채널(SSH·리버스셸·웹RCE) 무관 플래그 수집.

근본 원인 체인의 마지막 조각: 지금까지 플래그 읽기(FLAG_READS)는 SSH 전용(sshpass)이었다.
이 모듈은 **ShellSession 인터페이스로** user.txt/root.txt 를 읽어, 어떤 발판이든(리버스셸·웹RCE
포함) 같은 코드로 플래그를 수집한다. 실제 명령 실행은 session.run → (리버스셸/웹RCE면) 사용자가
주입한 transport 가 수행한다(= RCE 실행 표면). 이 모듈은 '어떤 명령을 읽고, 출력에서 플래그를
어떻게 분류'할지의 글루·파싱만 담당한다(생성 전용).
"""
from __future__ import annotations

from .flag import scan

# 발판 셸에서 user/root 플래그를 읽는 명령(분리 — 분류가 파일명으로 정확히 되도록).
USER_READS = [
    "cat ~/user.txt 2>/dev/null",
    "cat /home/*/user.txt 2>/dev/null",
    "cat /home/*/Desktop/user.txt 2>/dev/null",   # Windows/HTB 변형
]
ROOT_READS = [
    "cat /root/root.txt 2>/dev/null",
    "cat /root/Desktop/root.txt 2>/dev/null",
]


def flag_read_commands(flag_kind: str = "boot2root") -> list[str]:
    """발판 셸에서 돌릴 플래그 읽기 명령 목록(생성 전용 — 실행 아님).
    single(CTF) 이면 user/root 구분 없이 흔한 위치 몇 곳."""
    if flag_kind == "single":
        return ["cat flag.txt 2>/dev/null", "cat /flag* 2>/dev/null",
                "cat ~/flag.txt 2>/dev/null"]
    return [*USER_READS, *ROOT_READS]


def read_flags(session, flag_kind: str = "boot2root",
               prefixes: tuple[str, ...] = ()) -> dict[str, str]:
    """보유한 ShellSession 으로 플래그 파일을 읽어 {kind: value} 수집(채널 무관).
    session.run 이 실제 실행(발판 채널의 transport 가 수행 — RCE 실행 표면). 이 함수는
    어떤 명령을 돌리고 출력을 어떻게 분류할지의 글루·파싱만 한다(생성 전용).
    session 이 없거나 죽었으면 빈 결과(섣부른 실행 없음)."""
    out: dict[str, str] = {}
    if session is None or not getattr(session, "alive", False):
        return out
    for cmd in flag_read_commands(flag_kind):
        try:
            output = session.run(cmd)
        except Exception:
            continue   # 한 명령 실패가 전체 수집을 막지 않음
        for hit in scan(cmd, output or "", flag_kind=flag_kind, prefixes=prefixes):
            if hit.kind not in out:
                out[hit.kind] = hit.value
        # user+root 둘 다 모였으면 조기 종료(불필요한 실행 억제)
        if flag_kind != "single" and "user" in out and "root" in out:
            break
        if flag_kind == "single" and "flag" in out:
            break
    return out
