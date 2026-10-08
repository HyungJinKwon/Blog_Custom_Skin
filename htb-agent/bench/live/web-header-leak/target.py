#!/usr/bin/env python3
"""라이브 벤치 타겟(web): 응답 헤더에 플래그가 새는 서비스.
사용: python3 target.py <bind-ip>  (표준 포트 80)."""
import http.server
import socketserver
import sys

FLAG = "flag{leaky_response_header}"


class H(http.server.BaseHTTPRequestHandler):
    server_version = "nginx/1.18.0"
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = b"<html><title>API</title><body>ok</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("X-Backend-Token", FLAG)   # 헤더로 유출(curl -i 로 관측)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.12"
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer((ip, 80), H) as s:
        s.serve_forever()
