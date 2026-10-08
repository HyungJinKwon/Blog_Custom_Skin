"""
Sandbox — 셸 문법·스크립트를 쓰는 실행기 (완전자율 모드용)
============================================================

정적 범위 검사(ScopeGuard)는 명령 문자열만 본다. 스크립트 파일·계산된 주소·`-iL` 같은
간접 지정은 문자열에 대상이 드러나지 않아 정적 검사로는 막을 수 없다. 그래서 완전자율로
익스플로잇 스크립트까지 돌리려면 **실행 계층에서 네트워크를 강제**해야 한다.

  DockerSandbox — Kali 컨테이너 안에서 `bash -c` 로 실행. 컨테이너 시작 직후 root 로
                  iptables egress 정책(기본 DROP, 허용 대역만 ACCEPT)을 적용하고, 명령은
                  비root 사용자(`agent`) + no-new-privileges 로 실행 → 명령이 정책을 바꿀 수 없다.
                  기본 브리지 네트워크(내장 DNS 없음) + DNS 차단 → DNS 를 통한 외부 통신도 막힘.
                  contained=True.
  ShellRunner   — 로컬 `bash -c`(셸 문법만 지원). 네트워크 강제가 없으므로 contained=False —
                  오케스트레이터가 스크립트 실행·파일 쓰기 같은 '정적 검사 불가' 동작을 막는다.

두 실행기 모두 stdin 을 닫고, 작업공간(Workspace) 디렉터리를 현재 디렉터리로 쓴다.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
import uuid
from typing import Callable, Iterable

from .runner import RunOutput, _as_text

DEFAULT_IMAGE = "assassin-sandbox:latest"
SANDBOX_WORKDIR = "/work"
SANDBOX_USER = "agent"

Exec = Callable[..., "subprocess.CompletedProcess"]


class SandboxError(RuntimeError):
    """샌드박스 시작·정책 적용 실패 — 정책 없이 실행하지 않도록(fail-closed) 예외로 알린다."""


def _norm_cidrs(cidrs: Iterable[str]) -> list[str]:
    """허용 대역 정규화(IPv4 만). 잘못된 값은 예외 — 조용히 넓히지 않는다."""
    out: list[str] = []
    for c in cidrs:
        net = ipaddress.ip_network(str(c).strip(), strict=False)
        if net.version != 4:
            raise SandboxError(f"IPv6 대역은 샌드박스 egress 정책에서 지원하지 않음: {c}")
        if net.prefixlen == 0:
            raise SandboxError("0.0.0.0/0 은 허용 대역으로 쓸 수 없음(egress 전면 개방)")
        s = str(net)
        if s not in out:
            out.append(s)
    if not out:
        raise SandboxError("허용 대역이 비어 있음 — 샌드박스는 허용 대역이 하나 이상 필요")
    return out


def egress_rules(allow_cidrs: Iterable[str], lports: Iterable[int] = ()) -> str:
    """iptables-restore 입력(IPv4 filter 테이블). 기본 DROP, 허용 대역만 송신 허용.
    lports 는 허용 대역에서 들어오는 콜백(리버스쉘 등) 수신 포트."""
    cidrs = _norm_cidrs(allow_cidrs)
    lines = ["*filter", ":INPUT DROP [0:0]", ":FORWARD DROP [0:0]", ":OUTPUT DROP [0:0]",
             "-A INPUT -i lo -j ACCEPT",
             "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
             "-A OUTPUT -o lo -j ACCEPT",
             "-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"]
    for c in cidrs:
        lines.append(f"-A OUTPUT -d {c} -j ACCEPT")
        for p in lports:
            lines.append(f"-A INPUT -p tcp -s {c} --dport {int(p)} -j ACCEPT")
    lines.append("COMMIT")
    return "\n".join(lines) + "\n"


EGRESS_RULES_V6 = ("*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT DROP [0:0]\n"
                   "-A INPUT -i lo -j ACCEPT\n-A OUTPUT -o lo -j ACCEPT\nCOMMIT\n")


def _timeout_output(command: str, p: subprocess.CompletedProcess, timeout: int) -> RunOutput:
    """coreutils timeout 종료코드(124/137)를 타임아웃으로 변환."""
    out = RunOutput(command, _as_text(p.stdout), _as_text(p.stderr), p.returncode)
    if p.returncode in (124, 137):
        out.timed_out = True
        out.stderr = (out.stderr + f"\n[timeout {timeout}s]").strip()
    return out


class ShellRunner:
    """로컬 `bash -c` 실행기. 셸 문법은 되지만 네트워크 강제는 없다(contained=False)."""

    shell = True
    contained = False

    def __init__(self, workdir: str | None = None, exec_fn: Exec | None = None):
        self.workdir = workdir
        self._exec = exec_fn or subprocess.run

    def has_tool(self, binary: str) -> bool:
        return shutil.which(binary) is not None

    def run(self, command: str, timeout: int = 120) -> RunOutput:
        if not command.strip():
            return RunOutput(command, error="빈 명령", returncode=-1)
        bash = shutil.which("bash") or "/bin/bash"
        try:
            p = self._exec([bash, "-c", command], capture_output=True, text=True,
                           errors="replace", stdin=subprocess.DEVNULL,
                           timeout=timeout, cwd=self.workdir)
            return RunOutput(command, p.stdout or "", p.stderr or "", p.returncode)
        except subprocess.TimeoutExpired as e:
            return RunOutput(command, _as_text(e.stdout), _as_text(e.stderr),
                             returncode=-1, timed_out=True)
        except Exception as e:   # noqa: BLE001 — 실행 예외는 실패 결과로(파이프라인 보호)
            return RunOutput(command, error=f"예외: {type(e).__name__}: {e}", returncode=-1)


class DockerSandbox:
    """Kali 컨테이너 + iptables egress 강제 실행기(contained=True).

    수명주기: start() → run()* → stop(). start() 가 정책 적용·검증에 실패하면 컨테이너를
    지우고 SandboxError — 정책 없는 컨테이너에서 명령이 도는 일은 없다."""

    shell = True
    contained = True

    def __init__(self, workspace: str, allow_cidrs: Iterable[str],
                 image: str = DEFAULT_IMAGE, lports: Iterable[int] = (),
                 hosts: dict[str, str] | None = None, docker: str = "docker",
                 name: str | None = None, exec_fn: Exec | None = None):
        self.workspace = os.path.abspath(workspace)
        self.allow_cidrs = _norm_cidrs(allow_cidrs)
        self.image = image
        self.lports = [int(p) for p in lports]
        self.hosts = dict(hosts or {})
        self.docker = docker
        self.name = name or f"assassin-{uuid.uuid4().hex[:10]}"
        self._exec = exec_fn or subprocess.run
        self.started = False
        self._tools: dict[str, bool] = {}

    # ── 수명주기 ──
    def run_args(self) -> list[str]:
        """docker run 인자(테스트·감사용으로 분리)."""
        args = [self.docker, "run", "-d", "--rm", "--name", self.name,
                "--hostname", "assassin",
                "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
                "--security-opt", "no-new-privileges",
                "--pids-limit", "512", "--memory", "4g",
                "--dns", "127.0.0.1",          # 외부 DNS 미사용(egress 정책으로도 차단)
                "-v", f"{self.workspace}:{SANDBOX_WORKDIR}",
                "-w", SANDBOX_WORKDIR]
        for h, ip in sorted(self.hosts.items()):
            args += ["--add-host", f"{h}:{ip}"]
        for p in self.lports:
            args += ["-p", f"{p}:{p}"]
        return args + [self.image, "sleep", "infinity"]

    def _call(self, args: list[str], timeout: int = 60, input_text: str | None = None):
        kw: dict = dict(capture_output=True, text=True, errors="replace", timeout=timeout)
        if input_text is None:
            kw["stdin"] = subprocess.DEVNULL
        else:
            kw["input"] = input_text
        return self._exec(args, **kw)

    def start(self) -> None:
        if self.started:
            return
        os.makedirs(self.workspace, exist_ok=True)
        try:
            p = self._call(self.run_args(), timeout=120)
        except Exception as e:   # noqa: BLE001
            raise SandboxError(f"컨테이너 시작 실패: {type(e).__name__}: {e}") from e
        if p.returncode != 0:
            raise SandboxError("컨테이너 시작 실패: " + (_as_text(p.stderr).strip()[:300]
                                                     or f"rc={p.returncode}"))
        try:
            self._apply_policy()
        except Exception:
            self.stop()
            raise
        self.started = True

    def _apply_policy(self) -> None:
        root = [self.docker, "exec", "-i", "-u", "0", self.name]
        p = self._call(root + ["iptables-restore"], input_text=egress_rules(
            self.allow_cidrs, self.lports))
        if p.returncode != 0:
            raise SandboxError("egress 정책(iptables) 적용 실패: "
                               + _as_text(p.stderr).strip()[:300])
        # IPv6 는 전면 차단. ip6tables 가 없거나 커널이 IPv6 를 끈 경우엔 v6 경로 자체가 없다.
        self._call(root + ["ip6tables-restore"], input_text=EGRESS_RULES_V6)
        # 검증: 정책이 실제로 걸렸는지(OUTPUT 기본 DROP), 명령 사용자가 정책을 못 바꾸는지
        chk = self._call([self.docker, "exec", "-u", "0", self.name, "iptables", "-S", "OUTPUT"])
        if "-P OUTPUT DROP" not in _as_text(chk.stdout):
            raise SandboxError("egress 정책 검증 실패(OUTPUT 기본 DROP 아님)")
        tamper = self._call([self.docker, "exec", "-u", SANDBOX_USER, self.name,
                             "iptables", "-P", "OUTPUT", "ACCEPT"])
        if tamper.returncode == 0:
            raise SandboxError(f"'{SANDBOX_USER}' 사용자가 egress 정책을 바꿀 수 있음 — 중단")

    def stop(self) -> None:
        try:
            self._call([self.docker, "rm", "-f", self.name], timeout=30)
        except Exception:   # noqa: BLE001 — 정리 실패는 진행 방해 금지
            pass
        self.started = False

    def __enter__(self) -> "DockerSandbox":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    # ── 실행 ──
    def has_tool(self, binary: str) -> bool:
        b = os.path.basename(binary)
        if not re.fullmatch(r"[A-Za-z0-9_.+-]+", b):
            return True     # 경로·특수문자 바이너리는 실행 시점에 판정
        if b not in self._tools:
            try:
                p = self._call([self.docker, "exec", "-u", SANDBOX_USER, self.name,
                                "sh", "-c", f"command -v {b}"], timeout=15)
                self._tools[b] = p.returncode == 0
            except Exception:   # noqa: BLE001
                self._tools[b] = False
        return self._tools[b]

    def run(self, command: str, timeout: int = 120) -> RunOutput:
        if not self.started:
            return RunOutput(command, error="샌드박스 미시작", returncode=-1)
        if not command.strip():
            return RunOutput(command, error="빈 명령", returncode=-1)
        t = max(1, int(timeout))
        args = [self.docker, "exec", "-u", SANDBOX_USER, "-w", SANDBOX_WORKDIR,
                "-e", f"HOME={SANDBOX_WORKDIR}", self.name,
                "timeout", "-k", "5", str(t), "bash", "-c", command]
        try:
            p = self._call(args, timeout=t + 30)
        except subprocess.TimeoutExpired as e:
            return RunOutput(command, _as_text(e.stdout), _as_text(e.stderr),
                             returncode=-1, timed_out=True)
        except Exception as e:   # noqa: BLE001
            return RunOutput(command, error=f"샌드박스 실행 예외: {type(e).__name__}: {e}",
                             returncode=-1)
        return _timeout_output(command, p, t)


def allowlist_for(guard, resolver: Callable[[str], list[str]] | None = None
                  ) -> tuple[list[str], dict[str, str]]:
    """바인딩된 타겟만 egress 허용 대역으로(/32). 호스트명 타겟은 실행 전에 한 번 해석해
    IP 를 허용하고 컨테이너 /etc/hosts 로 고정한다(컨테이너 안에선 DNS 를 쓰지 않음)."""
    cidrs: list[str] = []
    hosts: dict[str, str] = {}
    if guard.bound_target is not None:
        cidrs.append(f"{guard.bound_target}/32")
    host = getattr(guard, "bound_host", None)
    if host:
        if resolver is None:
            import socket

            def resolver(h: str) -> list[str]:
                try:
                    return sorted(set(socket.gethostbyname_ex(h)[2]))
                except OSError:
                    return []
        ips = [ip for ip in resolver(host) if ipaddress.ip_address(ip).version == 4]
        for ip in ips:
            if f"{ip}/32" not in cidrs:
                cidrs.append(f"{ip}/32")
        if ips:
            hosts[host] = str(guard.bound_target) if guard.bound_target else ips[0]
    if not cidrs:
        raise SandboxError("타겟 IP 를 확정할 수 없음(호스트명 해석 실패) — egress 허용 대역을 만들 수 없음")
    return cidrs, hosts
