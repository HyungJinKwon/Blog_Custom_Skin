#!/usr/bin/env python3
"""라이브 벤치 타겟(web): 쿠키/권한 우회 — admin 권한 쿠키를 설정하면 플래그.
사용: python3 target.py <bind-ip>  (포트 80).
메인 페이지가 '관리자만 열람 가능'이라 알리고, 쿠키로 role 을 판별한다. role=admin 이면 플래그."""
import http.server
import socketserver
import sys

FLAG = "flag{cookie_role_bypass}"


class H(http.server.BaseHTTPRequestHandler):
    server_version = "Express"
    def log_message(self, *a):
        pass

    def _cookies(self) -> dict:
        raw = self.headers.get("Cookie", "") or ""
        out = {}
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                out[k.strip()] = v.strip()
        return out

    def do_GET(self):
        role = self._cookies().get("role", "guest")
        if self.path.split("?")[0].rstrip("/") in ("/admin", "") or self.path == "/":
            if role == "admin":
                body = f"<html><body><h1>Admin panel</h1><p>{FLAG}</p></body></html>"
            else:
                body = ("<html><body><h1>403</h1><p>admin only. "
                        "your role cookie is '" + role + "'. need role=admin.</p></body></html>")
            self.send_response(200 if role == "admin" else 403)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body.encode())
        else:
            self.send_error(404)


if __name__ == "__main__":
    ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.15"
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer((ip, 80), H) as s:
        s.serve_forever()
