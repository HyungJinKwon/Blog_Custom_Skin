"""
Cloud(AWS/S3) 열거 자동 준비 — 권한 확인 자산 전용
==================================================

타겟/호스트명/도메인에서 **S3 버킷명 후보**와 비인증 열거 명령을 '자동 생성'한다.
에이전트는 이 명령을 **실행하지 않는다** — AWS 엔드포인트는 타겟 범위(ScopeGuard)
밖이며, 실제 실행은 사용자가 권한 확인 자산에서 직접 수행한다(안전 경계 유지,
`revshell` 과 동일한 '생성 전용' 모델). 전부 표준 라이브러리만.

흐름:
  이름(호스트명/도메인/타겟) → 기저 토큰 → 접미/접두 조합으로 버킷 후보 생성
  → 후보별 비인증 S3 점검(aws s3 ls --no-sign-request / curl) + 도구(s3scanner·
    cloud_enum) + AWS 자격증명 확인 명령을 준비.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# 흔한 버킷 접미(공개 자산·백업 노출 패턴). "" 은 기저 이름 그대로.
_SUFFIXES = [
    "", "-backup", "-backups", "-dev", "-prod", "-staging",
    "-assets", "-static", "-files", "-data", "-media", "-uploads",
    "-web", "-s3", "-public", "-private", "-logs", "-bucket", "-archive",
]
# 버킷 후보에서 제외할 일반 라벨(TLD·흔한 서브도메인)
_STOP_LABELS = {
    "htb", "local", "localdomain", "com", "net", "org", "io", "co",
    "www", "mail", "ftp", "ns", "ns1", "ns2", "s3", "amazonaws",
}
_IP_RE = re.compile(r"^[0-9.]+$")
# S3 버킷 네이밍 규칙(간소화): 3~63자, 소문자/숫자/하이픈, 양끝은 영숫자
_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")


@dataclass
class CloudCheck:
    name: str
    command: str


@dataclass
class CloudPrep:
    candidates: list[str] = field(default_factory=list)
    checks: list[CloudCheck] = field(default_factory=list)
    keyword: str = ""


def _base_tokens(names: list[str]) -> list[str]:
    """호스트명/도메인/타겟에서 버킷명 기저 토큰을 추출(IP·TLD·흔한 라벨 제외)."""
    bases: list[str] = []

    def _add(tok: str) -> None:
        tok = tok.strip().lower()
        if tok and _BUCKET_RE.match(tok) and tok not in bases:
            bases.append(tok)

    for raw in names:
        raw = (raw or "").strip().lower()
        if not raw or _IP_RE.match(raw):
            continue
        raw = re.sub(r"^[a-z][a-z0-9+.-]*://", "", raw)   # 스킴 제거
        raw = raw.split("/")[0].split("?")[0].split(":")[0]  # 경로·쿼리·포트 제거
        if not raw or _IP_RE.match(raw):
            continue
        labels = [lbl for lbl in raw.split(".") if lbl and lbl not in _STOP_LABELS]
        for lbl in labels:
            _add(lbl)
        _add("".join(labels))   # 점 제거 결합(예: dev.acme → devacme)
        if len(labels) >= 2:
            _add("-".join(labels))
    return bases


def bucket_candidates(names: list[str], limit: int = 30) -> list[str]:
    """기저 토큰 × 접미 조합으로 버킷명 후보 생성(네이밍 규칙·중복·상한 적용).

    접미를 바깥 루프로 돌려 **모든 기저의 '맨이름(접미 없음)'이 먼저** 나오도록
    한다(한 기저가 상한을 독식해 다른 기저가 누락되는 것을 방지)."""
    bases = _base_tokens(names)
    out: list[str] = []
    for suf in _SUFFIXES:
        for base in bases:
            cand = base + suf
            if _BUCKET_RE.match(cand) and cand not in out:
                out.append(cand)
                if len(out) >= limit:
                    return out
    return out


def identity_checks() -> list[CloudCheck]:
    """AWS 자격증명/역할 확인(키 노출·IAM). 출처: AWS CLI 공식문서."""
    return [
        CloudCheck("자격증명 확인", "aws sts get-caller-identity"),
        CloudCheck("configure", "aws configure list"),
        CloudCheck("env 내 AWS 키", "env | grep -i aws"),
    ]


def generate(names: list[str], max_detailed: int = 8) -> CloudPrep:
    """이름 목록으로 S3/AWS 열거를 자동 준비(생성 전용). 후보가 없으면 비어있는
    CloudPrep 반환(호출측에서 생략 판단)."""
    bases = _base_tokens(names)
    cands = bucket_candidates(names)
    if not cands:
        return CloudPrep()

    checks: list[CloudCheck] = list(identity_checks())
    # 후보별 비인증 점검(상한까지만 상세 명령 — 나머지는 후보 목록으로 제공)
    for b in cands[:max_detailed]:
        checks.append(CloudCheck(f"s3 ls:{b}",
                                 f"aws s3 ls s3://{b} --no-sign-request"))
        checks.append(CloudCheck(f"http:{b}",
                                 f"curl -s -I https://{b}.s3.amazonaws.com/"))
    keyword = bases[0] if bases else ""
    if keyword:
        checks.append(CloudCheck("cloud_enum(멀티클라우드)",
                                 f"cloud_enum -k {keyword}"))
    checks.append(CloudCheck("s3scanner",
                             f"s3scanner scan --bucket {cands[0]}"))
    return CloudPrep(candidates=cands, checks=checks, keyword=keyword)


def render(names: list[str]) -> str:
    """사람이 보는 텍스트(블루/네이비 UI). 생성 전용 — 실행하지 않음."""
    from . import ui
    prep = generate(names)
    out = [ui.banner("AWS/S3 열거 자동 준비 (권한 확인 자산 전용)")]
    if not prep.candidates:
        out.append(ui.dim("버킷명 후보를 만들 이름(호스트명/도메인)이 없습니다 — "
                          "타겟이 IP 뿐이면 vhost/도메인 확인 후 재시도."))
        return "\n".join(out)
    out.append(ui.dim(f"기저 키워드={prep.keyword}  ·  후보 {len(prep.candidates)}개"
                      "  ·  생성만 함(에이전트는 실행 안 함 — AWS 는 범위 밖)\n"))
    out.append(ui.panel("버킷명 후보", [ui.bullet(c, "▸", "accent2")
                                     for c in prep.candidates], style="navy"))
    out.append(ui.rule("점검 명령 (비인증 열거 · 자격증명 · 도구)"))
    for c in prep.checks:
        out.append(ui.accent2(f"[{c.name}]"))
        out.append("  " + c.command)
    out.append(ui.rule())
    out.append(ui.dim("\n권한이 확인된 자산에서만 사용하세요. 출처: AWS CLI/S3 공식문서 · "
                      "s3scanner · cloud_enum."))
    return "\n".join(out)
