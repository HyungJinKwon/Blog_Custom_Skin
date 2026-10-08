#!/usr/bin/env python3
"""라이브 벤치 타겟(misc/net): 접속하면 인사말 후 잠시 뒤 플래그를 보내는 TCP 서비스.
사용: python3 target.py <bind-ip>  (포트 1337). nc 로 상호작용해 플래그 획득.
인사말은 즉시, 플래그는 1.2초 뒤에 보내 — 포트스캔의 짧은 배너 읽기엔 플래그가 안 잡히고
실제 nc 접속으로만 플래그가 나오도록(벤치 무결성)."""
import socket
import sys
import time

FLAG = "flag{netcat_banner_grab}"


def serve(ip: str, port: int = 1337) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((ip, port))
    srv.listen(8)
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            break
        try:
            conn.sendall(b"=== flag vault v1.0 ===\nconnection accepted.\n")
            time.sleep(1.2)
            conn.sendall(f"token: {FLAG}\n".encode())
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


if __name__ == "__main__":
    serve(sys.argv[1] if len(sys.argv) > 1 else "127.0.0.14")
