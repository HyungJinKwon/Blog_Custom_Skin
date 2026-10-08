#!/usr/bin/env python3
"""라이브 벤치 타겟(web): 메인 페이지 HTML 주석에 플래그가 남은 서비스.
사용: python3 target.py <bind-ip>  (표준 포트 80)."""
import http.server
import socketserver
import sys

FLAG = "flag{view_source_comment}"


class H(http.server.BaseHTTPRequestHandler):
    server_version = "Werkzeug/2.0.1"
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = (f"<html><head><title>Shop</title></head><body>\n"
                f"<!-- TODO: remove debug flag before prod: {FLAG} -->\n"
                f"<h1>Welcome</h1></body></html>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.13"
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer((ip, 80), H) as s:
        s.serve_forever()
