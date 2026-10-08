"""
KB Sync — 공유 저장소의 최신 번들 시드를 로컬에 자동 반영(검증 후 적용)
==========================================================================

문제: 번들 시드는 공유 저장소에서 계속 자란다(주간 자동 승격 워크플로). 그런데 각자의
로컬 사본은 사용자가 직접 git pull 하기 전까지 예전 지식에 머문다.

해결: 에이전트 실행 시(하루 1회) 공유 저장소의 시드 목록을 조회해, 로컬과 다른 시드만
내려받고, **승격 관문과 같은 품질 검증을 통과한 것만** 로컬 캐시
(<knowledge>/shared_seeds/, git 추적 안 함)에 둔다. 지식베이스는 로드 시 캐시본을
추적 시드 대신 쓴다.

원칙
  - 데이터(마크다운 노트)만 받는다. 코드·규칙·설정은 받지 않는다.
  - 저장소에 추적되는 파일은 건드리지 않는다 → git pull 충돌 없음.
  - 검증 실패·네트워크 오류는 조용히 건너뛴다(fail-safe: 기존 시드 그대로).
  - 사용자가 git pull 등으로 추적 시드를 갱신하면, 그 시드에 대한 캐시본은 자동으로
    무시된다(동기화 시점의 추적 시드 해시를 기록해 비교).
  - 로컬에서 직접 수정한(git 미커밋) 시드는 덮어쓰지 않는다(편집 중인 내용 보존).
  - 끄기: --no-kb-sync, --offline, 환경변수 ASSASSIN_NO_KB_SYNC=1.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field

from . import learn
from . import promote as _promote

DEFAULT_REPO = "HyungJinKwon/HTB_AUTO_AGENT"
SEED_PATH = "htb-agent/knowledge/notes/learned"
CACHE_DIRNAME = "shared_seeds"
MANIFEST = "manifest.json"
STAMP = ".last_sync"
INTERVAL = 24 * 3600                      # 자동 동기화 최소 간격(초)
MAX_BYTES = 64 * 1024                     # 내려받는 시드 1개 크기 상한
MIN_BYTES = 650                           # 시드 최소 크기(번들 시드 CI 불변식과 동일)
REQUIRED = ("## 개요", "## 핵심 기법", "## 표준 도구", "## 블루팀 탐지", "## 완화")
_SEED_NAME = re.compile(r"^seed-[a-z0-9][a-z0-9-]*\.md$")
_URL = re.compile(r"https?://[^\s)>\]]+")
_RAW_HOST = "raw.githubusercontent.com"


@dataclass
class SyncResult:
    applied: list[str] = field(default_factory=list)     # 캐시에 새로 반영한 시드
    cleared: list[str] = field(default_factory=list)     # 로컬이 최신이라 캐시에서 지운 시드
    rejected: list[tuple[str, str]] = field(default_factory=list)   # (파일, 사유)
    skipped: str = ""                                    # 동기화를 건너뛴 이유
    error: str = ""


def blob_sha(data: bytes) -> str:
    """git 블롭 해시(GitHub contents API 의 sha 와 같은 값)."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def validate_seed(name: str, text: str) -> str | None:
    """내려받은 시드 검증. 통과하면 None, 아니면 사유.
    번들 시드 CI 불변식 + 승격 관문을 그대로 적용한다."""
    if not _SEED_NAME.match(name):
        return "시드 파일명 형식 아님"
    if _promote._CONTROL.search(text):
        return "제어문자 포함"
    size = len(text.encode("utf-8"))
    if size < MIN_BYTES:
        return f"너무 짧음(<{MIN_BYTES}B)"
    if len(text) > _note_chars():
        return "RAG 반영 상한 초과"
    if not _promote.is_canonical(text):
        return "승격 섹션이 정규 형식 아님(섹션 안 임의 문장 등)"
    body, entries = _promote.split_seed(text)
    missing = [h for h in REQUIRED if h not in body]
    if missing:
        return f"필수 섹션 누락: {', '.join(missing)}"
    if not any(learn.is_allowed(u) for u in _URL.findall(body)):
        return "권위 출처 URL 없음"
    if len(entries) > _promote.MAX_ENTRIES:
        return "승격 항목 상한 초과"
    # 카탈로그 소속은 공유 저장소 CI 가 강제한다. 여기서 로컬 카탈로그로 다시 따지면
    # 코드가 예전인 사용자는 출처가 바뀐 최신 시드를 못 받으므로, 관문(허용 도메인 포함)만 적용.
    for e in entries:
        reason = _promote.check_candidate(e)
        if reason:
            return f"승격 항목 '{e.title}': {reason}"
    return None


def _note_chars() -> int:
    from .knowledge import NOTE_CHARS
    return NOTE_CHARS


def cache_dir(knowledge_dir: str) -> str:
    return os.path.join(knowledge_dir, CACHE_DIRNAME)


def _seed_dir(knowledge_dir: str) -> str:
    return os.path.join(knowledge_dir, "notes", "learned")


def _read_bytes(path: str) -> bytes | None:
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return None


def _load_manifest(cdir: str) -> dict:
    try:
        with open(os.path.join(cdir, MANIFEST), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_manifest(cdir: str, manifest: dict) -> None:
    tmp = os.path.join(cdir, MANIFEST + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=1, sort_keys=True)
    os.replace(tmp, os.path.join(cdir, MANIFEST))


def active_overlays(knowledge_dir: str) -> dict[str, str]:
    """지식베이스 로드 시 추적 시드 대신 쓸 캐시본 {파일명: 경로}.
    동기화 이후 추적 시드가 바뀌었으면(git pull 등) 그 캐시본은 쓰지 않는다."""
    cdir = cache_dir(knowledge_dir)
    if not os.path.isdir(cdir):
        return {}
    out: dict[str, str] = {}
    sdir = _seed_dir(knowledge_dir)
    for name, ent in _load_manifest(cdir).items():
        if not (isinstance(ent, dict) and ent.get("applied") and _SEED_NAME.match(name)):
            continue
        path = os.path.join(cdir, name)
        local = _read_bytes(os.path.join(sdir, name))
        if local is None or not os.path.isfile(path) or blob_sha(local) != ent.get("base"):
            continue
        out[name] = path
    return out


def _default_fetch(timeout: int = 6) -> Callable[[str], bytes | None]:
    def fetch(url: str) -> bytes | None:
        from .util import network_blocked
        if network_blocked():
            return None
        req = urllib.request.Request(url, headers={
            "User-Agent": "assassin-kb-sync", "Accept": "application/vnd.github+json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:   # noqa: S310 — https 고정
                data = resp.read(MAX_BYTES * 8 + 1)
            return data
        except Exception:   # noqa: BLE001 — 오프라인·차단·404 모두 '동기화 불가'로 처리
            return None
    return fetch


def _listing_url(repo: str, ref: str | None) -> str:
    url = f"https://api.github.com/repos/{repo}/contents/{SEED_PATH}"
    return url + (f"?ref={urllib.parse.quote(ref, safe='')}" if ref else "")


def _download_ok(url: str, repo: str) -> bool:
    p = urllib.parse.urlparse(url or "")
    return (p.scheme == "https" and p.hostname == _RAW_HOST
            and p.path.lower().startswith(f"/{repo.lower()}/"))


def sync(knowledge_dir: str, fetch: Callable[[str], bytes | None] | None = None,
         repo: str | None = None, ref: str | None = None) -> SyncResult:
    """공유 저장소의 시드와 로컬을 비교해, 다르고 검증을 통과한 것만 캐시에 반영."""
    res = SyncResult()
    repo = repo or os.environ.get("ASSASSIN_KB_SYNC_REPO") or DEFAULT_REPO
    ref = ref or os.environ.get("ASSASSIN_KB_SYNC_REF") or None
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        res.error = "저장소 형식 오류(owner/repo)"
        return res
    sdir = _seed_dir(knowledge_dir)
    if not os.path.isdir(sdir):
        res.error = "로컬 시드 디렉토리 없음"
        return res
    fetch = fetch or _default_fetch()
    raw = fetch(_listing_url(repo, ref))
    try:
        listing = json.loads(raw.decode("utf-8")) if raw else None
    except (UnicodeDecodeError, ValueError):
        listing = None
    if not isinstance(listing, list):
        res.error = "공유 저장소 목록 조회 실패(오프라인·비공개·차단)"
        return res
    try:
        _sync_into_cache(knowledge_dir, sdir, listing, fetch, repo, res)
    except OSError as e:          # 읽기 전용 설치·디스크 가득 등 — 실행을 막지 않고 보고만
        res.error = f"캐시 쓰기 실패: {e}"
    return res


def _known_locally(sdir: str, sha: str) -> bool:
    """공유본 블롭이 로컬 git 객체에 이미 있으면 True — 로컬 추적 시드가 그 버전을 거쳐
    커밋된(더 새로운) 상태이므로 캐시로 덮지 않는다. git 이 없거나 저장소가 아니면 False."""
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        return False
    try:
        out = subprocess.run(["git", "-C", sdir, "cat-file", "-e", sha],
                             capture_output=True, timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return out.returncode == 0


def _sync_into_cache(knowledge_dir: str, sdir: str, listing: list,
                     fetch: Callable[[str], bytes | None], repo: str, res: SyncResult) -> None:
    cdir = cache_dir(knowledge_dir)
    os.makedirs(cdir, exist_ok=True)
    manifest = _load_manifest(cdir)
    edited = _locally_modified(sdir)
    listed: set[str] = set()

    def clear(name: str) -> None:
        if manifest.pop(name, None) is not None or os.path.exists(os.path.join(cdir, name)):
            _remove(os.path.join(cdir, name))
            res.cleared.append(name)

    for item in listing:
        if not isinstance(item, dict):
            continue
        name, sha, url = item.get("name", ""), item.get("sha", ""), item.get("download_url", "")
        if not (isinstance(name, str) and _SEED_NAME.match(name) and isinstance(sha, str)):
            continue
        listed.add(name)
        local = _read_bytes(os.path.join(sdir, name))
        if local is None:            # 로컬에 없는 새 주제는 코드(카탈로그)와 함께 와야 한다
            continue
        base = blob_sha(local)
        raw_ent = manifest.get(name)
        ent: dict = raw_ent if isinstance(raw_ent, dict) else {}
        if sha == base:               # 로컬이 이미 최신 → 캐시본 정리
            clear(name)
            continue
        if ent.get("sha") == sha and ent.get("base") == base:
            continue                  # 이 버전은 이미 처리함
        if name in edited:
            res.rejected.append((name, "로컬 수정본(미커밋) 보존 — 동기화 안 함"))
            continue
        if _known_locally(sdir, sha):  # 로컬이 공유본을 거쳐 커밋된 더 새 버전
            clear(name)
            continue
        if not _download_ok(url, repo):
            res.rejected.append((name, "다운로드 주소가 공유 저장소 원본이 아님"))
            continue
        data = fetch(url)
        if not data or len(data) > MAX_BYTES:
            res.rejected.append((name, "내려받기 실패 또는 크기 초과"))
            continue
        if blob_sha(data) != sha:
            res.rejected.append((name, "내용 해시 불일치"))
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            res.rejected.append((name, "UTF-8 아님"))
            continue
        if text.replace("\r\n", "\n") == local.decode("utf-8", "replace").replace("\r\n", "\n"):
            clear(name)               # 줄바꿈만 다름(Windows autocrlf) — 로컬이 최신
            manifest[name] = {"sha": sha, "base": base, "applied": False}
            continue
        reason = validate_seed(name, text)
        if reason:
            res.rejected.append((name, reason))
            continue
        tmp = os.path.join(cdir, name + ".tmp")
        with open(tmp, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        os.replace(tmp, os.path.join(cdir, name))
        manifest[name] = {"sha": sha, "base": base, "applied": True}
        res.applied.append(name)
    for name in [n for n in list(manifest) if n not in listed]:   # 공유 저장소에서 사라진 시드
        clear(name)
    _save_manifest(cdir, manifest)
    _touch(os.path.join(cdir, STAMP))


def auto_sync(knowledge_dir: str, fetch: Callable[[str], bytes | None] | None = None,
              now: float | None = None, interval: int = INTERVAL) -> SyncResult:
    """실행 시 자동 동기화. 끄기 설정·간격 미도래면 건너뛴다."""
    if os.environ.get("ASSASSIN_NO_KB_SYNC", "").strip().lower() not in ("", "0", "false", "no", "off"):
        return SyncResult(skipped="ASSASSIN_NO_KB_SYNC")
    stamp = os.path.join(cache_dir(knowledge_dir), STAMP)
    now = time.time() if now is None else now
    try:
        if now - os.path.getmtime(stamp) < interval:
            return SyncResult(skipped="최근 동기화함")
    except OSError:
        pass
    res = sync(knowledge_dir, fetch=fetch)
    if res.error and os.path.isdir(_seed_dir(knowledge_dir)):
        try:                          # 오프라인이어도 매 실행마다 재시도(타임아웃 대기)하지 않도록
            os.makedirs(cache_dir(knowledge_dir), exist_ok=True)
        except OSError:
            pass
        _touch(stamp)
    return res


def _locally_modified(sdir: str) -> set[str]:
    """git 작업 트리에서 수정·미커밋 상태인 시드 파일명. git 이 없거나 저장소가 아니면 빈 집합."""
    try:
        out = subprocess.run(["git", "-C", sdir, "status", "--porcelain", "--", "."],
                             capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):
        return set()
    if out.returncode != 0:
        return set()
    return {os.path.basename(line[3:].strip().strip('"')) for line in out.stdout.splitlines()
            if len(line) > 3 and line[:2].strip()}


def _remove(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def _touch(path: str) -> None:
    try:
        with open(path, "a", encoding="utf-8"):
            pass
        os.utime(path, None)
    except OSError:
        pass


def knowledge_summary(knowledge_dir: str) -> dict:
    """리포트(심사위원용 '한눈에 보기')에 싣는 지식 기반 현황. 파일만 읽는다(네트워크 없음).
    seed_topics: 번들 시드 수 / catalog_topics·catalog_covered: 카탈로그 주제 수·시드 보유 수 /
    promoted: 승격 발췌 수(공유 캐시본이 있으면 그것, 없으면 추적 시드 기준) / promoted_latest: 최근 승격일 /
    shared_overlays: 공유 저장소 최신본으로 대체된 시드 수 / last_sync: 마지막 동기화(UTC ISO) /
    local_learned: 내 로컬 학습 노트 수 / ingested: 내가 넣은 자료 수."""
    sdir = _seed_dir(knowledge_dir)
    overlays = active_overlays(knowledge_dir) if os.path.isdir(sdir) else {}
    seeds = sorted(f for f in (os.listdir(sdir) if os.path.isdir(sdir) else [])
                   if _SEED_NAME.match(f))
    promoted, dates = 0, []
    for name in seeds:
        try:
            with open(overlays.get(name, os.path.join(sdir, name)), encoding="utf-8") as f:
                _, entries = _promote.split_seed(f.read())
        except OSError:
            continue
        promoted += len(entries)
        dates += [e.promoted_on for e in entries if e.promoted_on]
    stamp = os.path.join(cache_dir(knowledge_dir), STAMP)
    try:
        last_sync = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(os.path.getmtime(stamp)))
    except OSError:
        last_sync = ""
    learned = [f for f in (os.listdir(sdir) if os.path.isdir(sdir) else [])
               if f.startswith("learned-") and f.endswith(".md")]
    idir = os.path.join(knowledge_dir, "notes", "ingested")
    ingested = sum(len(fs) for _, _, fs in os.walk(idir)) if os.path.isdir(idir) else 0
    return {
        "seed_topics": len(seeds),
        "catalog_topics": len(learn.topics()),
        "catalog_covered": sum(f"seed-{t}.md" in seeds for t in learn.topics()),
        "promoted": promoted,
        "promoted_latest": max(dates) if dates else "",
        "shared_overlays": len(overlays),
        "last_sync": last_sync,
        "local_learned": len(learned),
        "ingested": ingested,
    }
