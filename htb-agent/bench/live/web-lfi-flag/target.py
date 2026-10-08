#!/usr/bin/env python3
"""라이브 벤치 타겟(web): LFI/경로 순회 — page 파라미터로 로컬 파일을 읽어 플래그.
사용: python3 target.py <bind-ip>  (포트 80).
/?page=home 처럼 페이지를 포함한다. 순회(../)로 /flag 를 읽으면 플래그. 샌드박스 가상 파일시스템
(실제 디스크 접근 없음 — 벤치 안전)."""
import http.server
import socketserver
import sys

FLAG = "flag{path_traversal_include}"
# 가상 파일시스템(실제 디스크를 열지 않는다 — 순회를 흉내만 냄)
VFS = {
    "home": "<h1>Home</h1><p>Welcome. Try ?page=home or ?page=about.</p>",
    "about": "<h1>About</h1><p>Demo site.</p>",
    "/flag": FLAG,
    "/etc/flag": FLAG,
    "flag": FLAG,
}


def _resolve(page: str) -> "str | None":
    p = page.strip()
    # 순회 토큰을 제거한 '정규화된' 꼬리를 본다(../../flag → flag, ....//etc/flag → /etc/flag)
    norm = p.replace("..", "").replace("//", "/")
    for key in (p, norm, "/" + norm.lstrip("/"), norm.lstrip("/")):
        if key in VFS:
            return VFS[key]
    # .html 붙여 서빙하는 흔한 패턴
    if p in VFS:
        return VFS[p]
    return None


class H(http.server.BaseHTTPRequestHandler):
    server_version = "Apache/2.4.54"
    def log_message(self, *a):
        pass

    def do_GET(self):
        from urllib.parse import parse_qs, urlparse
        q = parse_qs(urlparse(self.path).query)
        page = (q.get("page", ["home"])[0])
        content = _resolve(page)
        if content is None:
            content = f"<h1>Not found</h1><p>no such page: {page}</p>"
            code = 404
        else:
            code = 200
        body = f"<html><body>{content}</body></html>".encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.16"
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer((ip, 80), H) as s:
        s.serve_forever()
