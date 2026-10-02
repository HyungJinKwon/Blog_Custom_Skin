"""
Web Enum Parsers — gobuster / ffuf / feroxbuster 출력 구조화
============================================================

웹 디렉토리/vhost 퍼징 도구의 출력을 통째로 긁지 않고 파싱해, 발견된
경로/서브도메인과 상태코드·크기를 구조화한다.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field


@dataclass
class WebEntry:
    name: str                     # 경로 또는 vhost
    status: int | None = None
    size: int | None = None
    redirect: str = ""

    def __str__(self) -> str:
        s = self.name
        if self.status is not None:
            s += f" (Status {self.status}"
            if self.size is not None:
                s += f", {self.size}B"
            s += ")"
        if self.redirect:
            s += f" → {self.redirect}"
        return s


@dataclass
class WebEnumResult:
    tool: str
    entries: list[WebEntry] = field(default_factory=list)
    parse_error: str = ""

    def summary(self, top: int = 10) -> str:
        if not self.entries:
            return f"{self.tool}: 발견 0건" + (f" ({self.parse_error})" if self.parse_error else "")
        head = f"{self.tool}: {len(self.entries)}건"
        shown = self.entries[:top]
        body = "; ".join(str(e) for e in shown)
        more = f" …(+{len(self.entries) - top})" if len(self.entries) > top else ""
        return f"{head} — {body}{more}"


# gobuster dir:  /admin  (Status: 301) [Size: 312] [--> http://x/admin/]
_GOB_DIR = re.compile(
    r"^(?P<name>/\S*|\S+)\s+\(Status:\s*(?P<status>\d{3})\)"
    r"(?:\s*\[Size:\s*(?P<size>\d+)\])?"
    r"(?:\s*\[--> (?P<redir>[^\]]+)\])?"
)
# gobuster vhost:  Found: admin.machine.htb (Status: 200) [Size: 1234]
_GOB_VHOST = re.compile(
    r"^Found:\s+(?P<name>\S+)(?:\s+\(Status:\s*(?P<status>\d{3})\))?"
    r"(?:\s*\[Size:\s*(?P<size>\d+)\])?"
)


def parse_gobuster(text: str) -> WebEnumResult:
    res = WebEnumResult(tool="gobuster")
    if not text or not text.strip():
        res.parse_error = "빈 출력"
        return res
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("=", "-", "[", "Gobuster", "Starting", "Finished",
                                        "Progress")):
            # vhost 의 Found: 는 '['로 안 시작하므로 영향 없음
            if not line.startswith("Found:"):
                continue
        m = _GOB_VHOST.match(line) if line.startswith("Found:") else _GOB_DIR.match(line)
        if not m:
            continue
        gd = m.groupdict()
        res.entries.append(WebEntry(
            name=gd["name"],
            status=int(gd["status"]) if gd.get("status") else None,
            size=int(gd["size"]) if gd.get("size") else None,
            redirect=(gd.get("redir") or "").strip(),
        ))
    return res


def parse_ffuf_json(text: str) -> WebEnumResult:
    """ffuf -of json / -o out.json 결과."""
    res = WebEnumResult(tool="ffuf")
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError) as e:
        res.parse_error = f"JSON 파싱 실패: {e}"
        return res
    for r in data.get("results", []):
        inp = r.get("input", {})
        name = inp.get("FUZZ") or (next(iter(inp.values()), "") if inp else "") or r.get("url", "")
        res.entries.append(WebEntry(
            name=str(name),
            status=r.get("status"),
            size=r.get("length"),
            redirect=r.get("redirectlocation", "") or "",
        ))
    return res


# ffuf 텍스트:  admin  [Status: 200, Size: 1234, Words: 10, Lines: 5, Duration: 10ms]
_FFUF_TXT = re.compile(
    r"^(?P<name>\S+)\s+\[Status:\s*(?P<status>\d{3}),\s*Size:\s*(?P<size>\d+)"
)


def parse_ffuf_text(text: str) -> WebEnumResult:
    res = WebEnumResult(tool="ffuf")
    if not text or not text.strip():
        res.parse_error = "빈 출력"
        return res
    for raw in text.splitlines():
        m = _FFUF_TXT.match(raw.strip())
        if m:
            gd = m.groupdict()
            res.entries.append(WebEntry(name=gd["name"], status=int(gd["status"]),
                                        size=int(gd["size"])))
    return res


def parse_ffuf(text: str) -> WebEnumResult:
    """JSON 우선, 실패 시 텍스트."""
    stripped = (text or "").lstrip()
    if stripped.startswith("{"):
        r = parse_ffuf_json(text)
        if r.entries or not r.parse_error:
            return r
    return parse_ffuf_text(text)


# feroxbuster:  200      GET       10l       20w      300c http://x/admin
_FEROX = re.compile(r"^(?P<status>\d{3})\s+\w+\s+\d+l\s+\d+w\s+(?P<size>\d+)c\s+(?P<url>\S+)")


def parse_feroxbuster(text: str) -> WebEnumResult:
    res = WebEnumResult(tool="feroxbuster")
    if not text or not text.strip():
        res.parse_error = "빈 출력"
        return res
    for raw in text.splitlines():
        m = _FEROX.match(raw.strip())
        if m:
            gd = m.groupdict()
            res.entries.append(WebEntry(name=gd["url"], status=int(gd["status"]),
                                        size=int(gd["size"])))
    return res
