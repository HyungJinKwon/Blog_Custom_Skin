#!/usr/bin/env python3
"""라이브 벤치 타겟(web): robots.txt 가 숨은 경로를 흘리고, 그 경로에 플래그.
사용: python3 target.py <bind-ip>  (표준 포트 80 에 바인딩 — 전용 127.0.0.x)."""
import http.server
import socketserver
import sys

FLAG = "flag{robots_disclosed_path}"
HIDDEN = "/backup_2019"


class H(http.server.BaseHTTPRequestHandler):
    server_version = "Apache/2.4.41"
    def log_message(self, *a):
        pass

    def _send(self, body: bytes, ctype="text/plain"):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path == "/robots.txt":
            self._send(f"User-agent: *\nDisallow: {HIDDEN}/\n".encode())
        elif path == HIDDEN:
            self._send(f"<html><body>archive: {FLAG}</body></html>".encode(), "text/html")
        elif path == "/":
            self._send(b"<html><title>Welcome</title><body>Nothing here.</body></html>",
                       "text/html")
        else:
            self.send_error(404)


if __name__ == "__main__":
    ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.11"
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer((ip, 80), H) as s:
        s.serve_forever()
