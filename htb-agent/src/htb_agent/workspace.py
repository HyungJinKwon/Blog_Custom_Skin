"""
Workspace — 풀이 작업공간(챌린지 첨부파일 + 에이전트가 쓴 스크립트)
=====================================================================

Dreamhack/CTF 문제는 소스·바이너리·덤프 같은 **첨부파일**이 풀이의 출발점이다. 작업공간은

  files/   — `--files` 로 받은 첨부파일(zip/tar 는 안전하게 풀어 둠, 읽기 전용 취급)
  (그 외)  — LLM 이 쓴 익스플로잇 스크립트·페이로드 등

을 담고, 실행기(ShellRunner·DockerSandbox)의 현재 디렉터리가 된다. LLM 에는 파일 목록·
형식 판별과 소스 파일 발췌(크기 상한)를 넘겨 '제공 소스를 먼저 읽고 취약 지점을 찾는'
풀이가 가능하게 한다.

안전: 쓰기 경로는 작업공간 내부 상대경로만(절대경로·`..`·심볼릭 링크 탈출 거부), 크기 상한.
압축 해제도 같은 규칙(zip-slip·tar 링크/장치 파일 거부).
"""

from __future__ import annotations

import os
import shutil
import tarfile
import zipfile
from dataclasses import dataclass, field

MAX_WRITE_BYTES = 256 * 1024          # LLM 이 쓰는 파일 1개 상한
MAX_EXTRACT_BYTES = 200 * 1024 * 1024  # 압축 해제 총량 상한(압축 폭탄 방지)
MAX_EXTRACT_FILES = 5000

# LLM 컨텍스트에 본문을 발췌해 넣을 소스/설정 파일
_SOURCE_EXT = {
    ".py", ".js", ".ts", ".mjs", ".php", ".rb", ".go", ".java", ".kt", ".c", ".h", ".cpp",
    ".cc", ".rs", ".cs", ".sol", ".sh", ".sql", ".html", ".htm", ".ejs", ".j2", ".jinja",
    ".twig", ".tpl", ".yml", ".yaml", ".json", ".toml", ".ini", ".conf", ".cfg", ".xml",
    ".txt", ".md", ".sage", ".env",
}
_SOURCE_NAMES = {"dockerfile", "makefile", "requirements.txt", "package.json",
                 "docker-compose.yml", "docker-compose.yaml", "nginx.conf", ".htaccess"}
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}


class WorkspaceError(ValueError):
    """작업공간 경로·크기 규칙 위반."""


@dataclass
class FileInfo:
    path: str      # 작업공간 기준 상대경로
    size: int
    kind: str      # elf / pe / zip / pcap / image / text / data …


@dataclass
class Workspace:
    root: str
    imported: list[str] = field(default_factory=list)   # files/ 아래 상대경로
    written: list[str] = field(default_factory=list)    # LLM 이 쓴 파일

    def __post_init__(self) -> None:
        self.root = os.path.realpath(self.root)
        os.makedirs(self.root, exist_ok=True)

    # ── 경로 ──
    def resolve(self, rel: str) -> str:
        """작업공간 내부 상대경로 → 실제 경로. 밖으로 나가면 WorkspaceError."""
        rel = (rel or "").strip()
        if rel.startswith("/work/"):          # 샌드박스 안 경로 표기 허용
            rel = rel[len("/work/"):]
        if not rel or os.path.isabs(rel) or "\x00" in rel:
            raise WorkspaceError(f"작업공간 상대경로만 허용: {rel!r}")
        parts = rel.replace("\\", "/").split("/")
        if any(p == ".." for p in parts):
            raise WorkspaceError(f"'..' 경로 거부: {rel!r}")
        full = os.path.realpath(os.path.join(self.root, rel))
        if full != self.root and not full.startswith(self.root + os.sep):
            raise WorkspaceError(f"작업공간 밖 경로 거부: {rel!r}")
        return full

    # ── 쓰기 ──
    def write_file(self, rel: str, content: str, executable: bool = False) -> str:
        data = content.encode("utf-8")
        if len(data) > MAX_WRITE_BYTES:
            raise WorkspaceError(f"파일이 너무 큼({len(data)}B > {MAX_WRITE_BYTES}B)")
        full = self.resolve(rel)
        norm = os.path.relpath(full, self.root)
        if norm == "files" or norm.startswith("files" + os.sep):
            raise WorkspaceError("files/ 는 첨부파일 전용(읽기 전용) — 다른 경로에 쓰세요")
        os.makedirs(os.path.dirname(full), exist_ok=True)
        tmp = full + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, full)
        os.chmod(full, 0o755 if (executable or content.startswith("#!")) else 0o644)
        if norm not in self.written:
            self.written.append(norm)
        return norm

    # ── 첨부파일 가져오기 ──
    def import_paths(self, paths: list[str]) -> list[str]:
        """파일/디렉터리를 files/ 로 복사하고 zip·tar 는 files/<이름>/ 에 풀어 둔다."""
        dest_root = os.path.join(self.root, "files")
        os.makedirs(dest_root, exist_ok=True)
        added: list[str] = []
        for src in paths:
            src = os.path.expanduser(src)
            if not os.path.exists(src):
                raise WorkspaceError(f"첨부파일 없음: {src}")
            name = os.path.basename(os.path.normpath(src))
            dst = os.path.join(dest_root, name)
            if os.path.isdir(src):
                shutil.copytree(src, dst, dirs_exist_ok=True, symlinks=False,
                                ignore=shutil.ignore_patterns(*_SKIP_DIRS))
            else:
                shutil.copy2(src, dst)
                base = name
                for ext in (".tar.gz", ".tgz", ".tar.xz", ".tar.bz2", ".tar", ".zip"):
                    if name.lower().endswith(ext):
                        base = name[: -len(ext)]
                        break
                if zipfile.is_zipfile(dst):
                    _safe_unzip(dst, os.path.join(dest_root, base + "_x"))
                elif tarfile.is_tarfile(dst):
                    _safe_untar(dst, os.path.join(dest_root, base + "_x"))
            added.append(os.path.relpath(dst, self.root))
        self.imported += [a for a in added if a not in self.imported]
        return added

    # ── 조회(LLM 컨텍스트) ──
    def inventory(self, limit: int = 60) -> list[FileInfo]:
        out: list[FileInfo] = []
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
            for fn in sorted(filenames):
                full = os.path.join(dirpath, fn)
                if os.path.islink(full) or not os.path.isfile(full):
                    continue
                rel = os.path.relpath(full, self.root)
                out.append(FileInfo(rel, os.path.getsize(full), sniff(full)))
                if len(out) >= limit:
                    return out
        return out

    def context_lines(self, excerpt_budget: int = 12000, per_file: int = 4000) -> list[str]:
        """LLM 용: 파일 목록 + 소스 발췌(총량 상한). 본문은 신뢰불가 데이터로 표시."""
        inv = self.inventory()
        if not inv:
            return []
        lines = [f"{fi.path}  ({fi.size}B, {fi.kind})" for fi in inv]
        budget = excerpt_budget
        for fi in inv:
            if budget <= 0:
                break
            if fi.kind != "text" or not _is_source(fi.path):
                continue
            try:
                with open(os.path.join(self.root, fi.path), encoding="utf-8",
                          errors="replace") as f:
                    body = f.read(min(per_file, budget))
            except OSError:
                continue
            budget -= len(body)
            more = " …(생략)" if fi.size > len(body.encode("utf-8")) else ""
            lines.append(f"--- {fi.path}{more} ---\n{body}")
        return lines


def _is_source(rel: str) -> bool:
    name = os.path.basename(rel).lower()
    return name in _SOURCE_NAMES or os.path.splitext(name)[1] in _SOURCE_EXT


def sniff(path: str) -> str:
    """매직 바이트로 대략적 형식 판별(외부 `file` 없이)."""
    try:
        with open(path, "rb") as f:
            head = f.read(512)
    except OSError:
        return "unreadable"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head.startswith(b"MZ"):
        return "pe"
    if head.startswith(b"PK\x03\x04"):
        return "zip"
    if head[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"):
        return "pcap"
    if head.startswith((b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"BM")):
        return "image"
    if head.startswith(b"%PDF"):
        return "pdf"
    if head.startswith((b"\x1f\x8b", b"BZh", b"\xfd7zXZ")):
        return "compressed"
    if not head:
        return "empty"
    if b"\x00" in head:
        return "data"
    try:
        head.decode("utf-8")
        return "text"
    except UnicodeDecodeError:
        return "data"


def _inside(root: str, name: str) -> str:
    root = os.path.realpath(root)
    full = os.path.realpath(os.path.join(root, name))
    if full != root and not full.startswith(root + os.sep):
        raise WorkspaceError(f"압축 항목이 작업공간 밖을 가리킴(zip-slip): {name!r}")
    return full


def _safe_unzip(src: str, dest: str) -> None:
    with zipfile.ZipFile(src) as z:
        infos = z.infolist()
        if len(infos) > MAX_EXTRACT_FILES:
            raise WorkspaceError(f"압축 항목 수 초과({len(infos)})")
        if sum(i.file_size for i in infos) > MAX_EXTRACT_BYTES:
            raise WorkspaceError("압축 해제 총량 상한 초과")
        for i in infos:
            target = _inside(dest, i.filename)
            if i.is_dir():
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with z.open(i) as r, open(target, "wb") as w:
                shutil.copyfileobj(r, w)


def _safe_untar(src: str, dest: str) -> None:
    with tarfile.open(src) as t:
        members = t.getmembers()
        if len(members) > MAX_EXTRACT_FILES:
            raise WorkspaceError(f"압축 항목 수 초과({len(members)})")
        if sum(m.size for m in members if m.isfile()) > MAX_EXTRACT_BYTES:
            raise WorkspaceError("압축 해제 총량 상한 초과")
        for m in members:
            target = _inside(dest, m.name)
            if m.isdir():
                os.makedirs(target, exist_ok=True)
            elif m.isfile():
                os.makedirs(os.path.dirname(target), exist_ok=True)
                r = t.extractfile(m)
                if r is None:
                    continue
                with r, open(target, "wb") as w:
                    shutil.copyfileobj(r, w)
            # 링크·장치·FIFO 는 건너뜀(탈출·특수파일 방지)
