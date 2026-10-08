"""
LiveBench — 실제 서비스를 상대로 한 풀이 벤치마크(진짜 도구 실행)
====================================================================

오프라인 `--bench`(bench/challenges/*.json)는 FakeRunner 로 가짜 응답만 돌려준다. LiveBench 는
**진짜 취약 서비스를 띄우고, 진짜 도구를 실행해, 진짜 플래그를 잡았는지**를 측정한다 — 발표·심사용
수치(pass@k·검증된 풀이율·시간)를 신뢰할 수 있게 만든다.

두 가지 타겟 종류(challenge.json 의 "kind"):
  loopback — 파이썬으로 구현한 취약 서비스를 전용 127.0.0.x 주소 + 표준 포트에 띄운다.
             nmap 없이도 소켓 폴백으로 포트를 찾고 curl 등 실도구로 푼다(루트면 어디서나 실행).
  docker   — challenge 디렉터리의 Dockerfile 로 컨테이너를 빌드·실행하고 전용 IP(표준 포트)로
             푼다. 실제 FTP/Redis/SMB 등 무거운 서비스용. Docker 데몬이 있을 때만.

각 타겟은 **자신의 IP** 를 가지므로 서비스가 표준 포트(80/21/6379…)에 떠서, 에이전트의 기존 흐름
(정찰→프로파일→열거→curl http://IP/…)이 포트 조작 없이 그대로 동작한다. 범위 가드는 타겟 IP 만
허용(loopback 대역 또는 docker 네트워크 /32)해 범위 밖으로 나가지 않는다.

결과 집계·렌더링은 오프라인 bench 와 같은 구조(AttemptResult/ChallengeStats)를 재사용한다.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .bench import AttemptResult

# loopback 타겟에 할당할 127.0.0.x 주소 풀(.0.1 은 흔한 서비스와 겹칠 수 있어 .11 부터).
_LOOPBACK_BASE = 11


@dataclass
class LiveChallenge:
    name: str
    title: str
    flag: str
    kind: str                       # loopback | docker
    dir: Path
    difficulty: str = "medium"
    category: str = ""              # web/pwn/rev/... (Jeopardy LLM 힌트)
    platform: str = "ctf"           # htb | dreamhack | ctf
    ports: list = field(default_factory=list)      # [(포트, 서비스)] — 소켓 폴백 힌트·준비성 확인
    target: str = ""                # loopback: 스크립트 파일명 / docker: 이미지/컨텍스트
    ready_timeout: float = 20.0
    lesson: str = ""


class LiveBenchError(RuntimeError):
    pass


def load_live_suite(path: str) -> list[LiveChallenge]:
    """디렉터리 아래 각 하위폴더의 challenge.json 을 읽어 LiveChallenge 목록으로."""
    root = Path(path)
    if not root.is_dir():
        raise LiveBenchError(f"라이브 문제 디렉터리 없음: {path}")
    out: list[LiveChallenge] = []
    for cj in sorted(root.glob("*/challenge.json")):
        try:
            d = json.loads(cj.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise LiveBenchError(f"{cj}: 읽기 실패 — {e}") from e
        missing = [k for k in ("name", "title", "flag", "kind") if not d.get(k)]
        if missing:
            raise LiveBenchError(f"{cj}: 필수 키 없음 — {', '.join(missing)}")
        out.append(LiveChallenge(
            name=str(d["name"]), title=str(d["title"]), flag=str(d["flag"]),
            kind=str(d["kind"]), dir=cj.parent,
            difficulty=str(d.get("difficulty") or "medium"),
            category=str(d.get("category") or ""),
            platform=str(d.get("platform") or "ctf"),
            ports=[(int(n), str(s)) for n, s in (d.get("ports") or [])],
            target=str(d.get("target") or ""),
            ready_timeout=float(d.get("ready_timeout") or 20.0),
            lesson=str(d.get("lesson") or "")))
    if not out:
        raise LiveBenchError(f"challenge.json 을 찾지 못함: {path}/*/challenge.json")
    return out


def _wait_port(host: str, port: int, timeout: float) -> bool:
    """서비스가 접속을 받을 때까지 대기(준비성 확인). 되면 True."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.3)
    return False


class Target:
    """타겟 수명주기 인터페이스. start() 후 self.address 로 접속 가능해야 한다."""
    address: str = ""
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def __enter__(self):
        self.start()
        return self
    def __exit__(self, *exc) -> None:
        self.stop()


class LoopbackTarget(Target):
    """전용 127.0.0.x 주소 + 표준 포트에 파이썬 취약 서비스를 띄운다.
    challenge 디렉터리의 target 스크립트를 `python3 <script> <bind-ip>` 로 실행한다."""

    def __init__(self, ch: LiveChallenge, index: int,
                 popen: Callable | None = None):
        self.ch = ch
        self.address = f"127.0.0.{_LOOPBACK_BASE + index}"
        self._popen = popen or subprocess.Popen
        self._proc: "subprocess.Popen | None" = None

    def start(self) -> None:
        if not self.ch.target:
            raise LiveBenchError(f"{self.ch.name}: loopback 타겟은 target 스크립트가 필요")
        script = self.ch.dir / self.ch.target
        if not script.is_file():
            raise LiveBenchError(f"{self.ch.name}: 타겟 스크립트 없음 — {script}")
        # -I: 격리 모드(현재 디렉터리·환경 sys.path 오염 방지). 스크립트는 신뢰된 벤치 자산.
        # cwd 를 challenge 디렉터리로 두고 스크립트는 파일명만 전달(경로 중복 방지)
        self._proc = self._popen(
            [sys.executable, "-I", self.ch.target, self.address],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            cwd=str(self.ch.dir))
        port = self.ch.ports[0][0] if self.ch.ports else 80
        if not _wait_port(self.address, port, self.ch.ready_timeout):
            err = ""
            if self._proc and self._proc.poll() is not None and self._proc.stderr:
                try:
                    err = self._proc.stderr.read().decode("utf-8", "replace")[:300]
                except OSError:
                    err = ""
            self.stop()
            raise LiveBenchError(f"{self.ch.name}: 서비스 준비 실패({self.address}:{port}) {err}")

    def stop(self) -> None:
        p = self._proc
        if p is None:
            return
        try:
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        except Exception:   # noqa: BLE001 — 정리 실패는 진행 방해 금지
            pass
        self._proc = None


class DockerTarget(Target):
    """challenge 디렉터리의 Dockerfile 로 컨테이너를 빌드·실행. 전용 네트워크에서 IP 를 받아
    표준 포트로 서비스한다. 실제 Docker 데몬 필요(없으면 LiveBenchError). exec_fn 주입 가능(테스트)."""

    def __init__(self, ch: LiveChallenge, network: str = "assassin-bench",
                 image_prefix: str = "assassin-bench", docker: str = "docker",
                 exec_fn: Callable | None = None):
        self.ch = ch
        self.network = network
        self.image = f"{image_prefix}-{ch.name}:latest"
        self.cname = f"assassin-bench-{ch.name}"
        self.docker = docker
        self._exec = exec_fn or subprocess.run
        self.address = ""

    def _run(self, args, timeout=300, input_text=None):
        kw: dict = dict(capture_output=True, text=True, errors="replace", timeout=timeout)
        if input_text is None:
            kw["stdin"] = subprocess.DEVNULL
        else:
            kw["input"] = input_text
        return self._exec([self.docker, *args], **kw)

    def _ok(self, p, what: str):
        if getattr(p, "returncode", 1) != 0:
            raise LiveBenchError(f"{self.ch.name}: {what} 실패 — "
                                 + (getattr(p, "stderr", "") or "").strip()[:200])
        return p

    def start(self) -> None:
        ctx = self.ch.dir
        if not (ctx / "Dockerfile").is_file():
            raise LiveBenchError(f"{self.ch.name}: Dockerfile 없음 — {ctx}/Dockerfile")
        # 네트워크(있으면 재사용 — 실패해도 치명적이지 않음)
        self._run(["network", "create", self.network], timeout=60)
        self._ok(self._run(["build", "-t", self.image, str(ctx)], timeout=600), "이미지 빌드")
        self._run(["rm", "-f", self.cname], timeout=60)
        self._ok(self._run(["run", "-d", "--rm", "--name", self.cname,
                            "--network", self.network, self.image], timeout=120), "컨테이너 실행")
        insp = self._ok(self._run(
            ["inspect", "-f",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", self.cname],
            timeout=60), "IP 조회")
        ip = (insp.stdout or "").strip().splitlines()[0].strip() if insp.stdout else ""
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            self.stop()
            raise LiveBenchError(f"{self.ch.name}: 컨테이너 IP 확인 실패({ip!r})")
        self.address = ip
        port = self.ch.ports[0][0] if self.ch.ports else 80
        if not _wait_port(ip, port, self.ch.ready_timeout):
            self.stop()
            raise LiveBenchError(f"{self.ch.name}: 서비스 준비 실패({ip}:{port})")

    def stop(self) -> None:
        try:
            self._run(["rm", "-f", self.cname], timeout=60)
        except Exception:   # noqa: BLE001
            pass


def docker_available(docker: str = "docker", exec_fn: Callable | None = None) -> bool:
    """Docker 데몬이 실제로 응답하는지 확인(바이너리 존재 ≠ 데몬 기동)."""
    import shutil
    if exec_fn is None and not shutil.which(docker):
        return False
    run = exec_fn or subprocess.run
    try:
        p = run([docker, "info", "--format", "{{.ServerVersion}}"],
                capture_output=True, text=True, timeout=15, stdin=subprocess.DEVNULL)
    except Exception:   # noqa: BLE001
        return False
    return getattr(p, "returncode", 1) == 0


def make_target(ch: LiveChallenge, index: int, **kw) -> Target:
    if ch.kind == "loopback":
        return LoopbackTarget(ch, index, popen=kw.get("popen"))
    if ch.kind == "docker":
        return DockerTarget(ch, network=kw.get("network", "assassin-bench"),
                            image_prefix=kw.get("image_prefix", "assassin-bench"),
                            exec_fn=kw.get("docker_exec"))
    raise LiveBenchError(f"{ch.name}: 알 수 없는 kind — {ch.kind!r}")


def run_live_attempt(ch: LiveChallenge, n: int, index: int, kb, router=None,
                     trace_path: str = "", runner=None, target: Target | None = None,
                     **orch_kw) -> AttemptResult:
    """타겟을 띄우고 '진짜' 에이전트를 돌려 플래그 획득 여부를 측정한다.
    runner 미지정 시 실제 SubprocessRunner(진짜 도구 실행). target 주입 시 그대로 사용(테스트)."""
    from .audit import AuditLog, NullAudit
    from .orchestrator import Orchestrator
    from .scope_guard import ScopeGuard
    from .tools.recon import auto_approve_in_scope
    from .tools.runner import SubprocessRunner

    tgt = target or make_target(ch, index, **orch_kw.pop("target_kw", {}))
    audit = AuditLog(trace_path) if trace_path else NullAudit()
    calls0 = getattr(router, "calls", 0) if router else 0
    cost0 = float(getattr(router, "total_cost", 0.0) or 0.0) if router else 0.0
    prefixes = tuple(dict.fromkeys(
        [ch.flag.split("{", 1)[0]] if "{" in ch.flag else []) or ("flag",))
    t0 = time.monotonic()
    solved = verified = False
    executed = proposed = approvals = steps = 0
    try:
        tgt.start()
        guard = ScopeGuard.from_cidr_strings(
            [f"{tgt.address}/32"], enforce_ranges=True, allow_hostname_target=True)
        guard.bind_target(tgt.address)
        extra = [p for p, _ in ch.ports]
        orc = Orchestrator(
            guard, runner or SubprocessRunner(), kb, auto_approve_in_scope,
            llm_router=router, flag_kind="single", flag_prefixes=prefixes,
            platform_name={"htb": "Hack The Box", "dreamhack": "Dreamhack"}.get(
                ch.platform, "CTF"),
            category=ch.category, recon_extra_ports=extra, quiet=True, audit=audit,
            **orch_kw)
        rep = orc.run()
        solved = any(f.value == ch.flag for f in rep.flags)
        verified = any(p.value == ch.flag and p.verdict == "exploit-derived"
                       for p in getattr(rep, "flag_provenance", []))
        gs = rep.gate_stats
        executed = int(gs.get("executed", 0))
        proposed = int(gs.get("proposed", 0))
        approvals = int(gs.get("denied_review", 0)) + int(gs.get("denied_scope", 0))
        if solved:
            ran = [f for f in rep.enum_findings + rep.llm_findings if f.ran]
            for i, f in enumerate(ran, 1):
                if ch.flag in (f.output or "") or "🚩" in (f.note or ""):
                    steps = i
                    break
    finally:
        tgt.stop()
        audit.close()
    return AttemptResult(
        challenge=ch.name, attempt=n, solved=solved, executed=executed, proposed=proposed,
        elapsed_sec=round(time.monotonic() - t0, 3), steps_to_flag=steps, verified=verified,
        approvals_needed=approvals,
        llm_calls=(getattr(router, "calls", 0) - calls0) if router else 0,
        cost=round((float(getattr(router, "total_cost", 0.0) or 0.0) - cost0) if router else 0.0, 6),
        trace=trace_path)


def run_live_bench(challenges: list[LiveChallenge], attempts: int = 1, kb=None, router=None,
                   trace_dir: str = "", progress: Callable[[str], None] | None = None,
                   runner=None, **orch_kw) -> list[AttemptResult]:
    if kb is None:
        from .knowledge import KnowledgeBase
        kb = KnowledgeBase.load()
    attempts = max(1, int(attempts))
    results: list[AttemptResult] = []
    if trace_dir:
        os.makedirs(trace_dir, exist_ok=True)
    for index, ch in enumerate(challenges):
        for n in range(1, attempts + 1):
            trace = os.path.join(trace_dir, f"{ch.name}_{n}.jsonl") if trace_dir else ""
            try:
                r = run_live_attempt(ch, n, index, kb, router=router, trace_path=trace,
                                     runner=runner, **orch_kw)
            except Exception as e:   # noqa: BLE001 — 한 문제의 셋업 실패가 전체를 멈추지 않도록
                r = AttemptResult(challenge=ch.name, attempt=n, solved=False, executed=0,
                                  proposed=0, elapsed_sec=0.0, trace=trace)
                if progress:
                    progress(f"{ch.name} #{n}: 셋업/실행 오류 — {type(e).__name__}: {e}")
                results.append(r)
                continue
            results.append(r)
            if progress:
                progress(f"{ch.name} #{n}: {'성공' if r.solved else '실패'}"
                         f"{'(검증)' if r.verified else ''} "
                         f"(명령 {r.executed}개, {r.elapsed_sec:.2f}초)")
    return results
