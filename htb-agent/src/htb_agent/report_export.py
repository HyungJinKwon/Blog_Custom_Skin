"""
Report Export — 세션 결과를 구조화 포맷으로 내보내기
=====================================================

OrchestrationReport 를 (1) 기계판독 JSON 과 (2) 자체완결 HTML 대시보드로 변환한다.
순수 표준 라이브러리만 사용하고 네트워크를 쓰지 않는다. 외부 도구/파이프라인 연계와
가독성(§6 블루/네이비)을 위한 산출물이다.

  - to_dict(report)  : 직렬화 가능한 dict (안정적 스키마, schema_version 포함)
  - to_json(report)  : UTF-8 JSON 문자열(한글 보존)
  - to_html(report)  : 인라인 CSS HTML(외부 의존 0, 블루/네이비)

HTML 은 사용자 제공 값/배너를 그대로 렌더링하므로 반드시 escape 한다(XSS/깨짐 방지).
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from .enrich import CWE_NAMES, Enricher

SCHEMA_VERSION = "1.0"


# ──────────────────────────────────────────────────────────────────────
# 직렬화 (dict / JSON)
# ──────────────────────────────────────────────────────────────────────
def _port_dict(p) -> dict:
    return {
        "port": p.port, "proto": p.proto, "state": p.state,
        "service": p.service or "", "product": p.product or "",
        "version": p.version or "", "banner": p.banner,
    }


def _finding_dict(f) -> dict:
    return {"command": f.command, "ran": f.ran, "phase": f.phase,
            "note": f.note, "output": f.output}


def _vuln_dict(m) -> dict:
    return {"name": m.name, "cve": list(m.cve), "cwe": list(m.cwe),
            "severity": m.severity, "note": m.note, "matched_on": m.matched_on,
            "suggest": list(m.suggest), "source": m.source}


def _cve_dict(e) -> dict:
    return {"id": e.id, "description": e.description, "cvss": e.cvss,
            "severity": e.severity, "cwe": list(e.cwe),
            "references": list(e.references), "poc_repos": list(e.poc_repos),
            "source": e.source}


def to_dict(report) -> dict:
    """OrchestrationReport → 직렬화 가능한 dict(안정 스키마)."""
    host = report.host
    prof = report.profile
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": "ASSASSIN",
        "target": report.target,
        "status": report.status,
        "message": report.message,
        "flag_kind": report.flag_kind,
        "os": {
            "class": prof.os_class.value if prof else "unknown",
            "tag": prof.tag if prof else "",
            "confidence": prof.confidence if prof else 0,
            "is_domain_controller": prof.is_domain_controller if prof else False,
        },
        "open_ports": host.open_ports if host else [],
        "ports": [_port_dict(p) for p in host.ports] if host else [],
        "enum_findings": [_finding_dict(f) for f in report.enum_findings],
        "llm_findings": [_finding_dict(f) for f in report.llm_findings],
        "detected_cve": list(report.detected_cve),
        "detected_cwe": list(report.detected_cwe),
        "vuln_matches": [_vuln_dict(m) for m in report.vuln_matches],
        "enriched": [_cve_dict(e) for e in report.enriched],
        "flags": [{"value": f.value, "kind": f.kind, "source": f.source}
                  for f in report.flags],
        "user_flag": report.user_flag,
        "root_flag": report.root_flag,
        "manual_suggestions": list(report.manual_suggestions),
        "revshell": {
            "lhost": getattr(report, "revshell_lhost", ""),
            "lport": getattr(report, "revshell_lport", 0),
            "payloads": [{"name": s.name, "payload": s.payload}
                         for s in getattr(report, "revshells", [])],
        },
    }


def to_json(report, indent: int = 2) -> str:
    return json.dumps(to_dict(report), ensure_ascii=False, indent=indent)


# ──────────────────────────────────────────────────────────────────────
# HTML 대시보드 (블루/네이비 · 인라인 CSS · 외부 의존 0)
# ──────────────────────────────────────────────────────────────────────
_CSS = """
:root{--bg:#0b1220;--panel:#111c31;--panel2:#16233c;--line:#26406b;}
*{box-sizing:border-box}
body{margin:0;background:#0b1220;color:#dce6f5;font:14px/1.6 -apple-system,
 "Segoe UI",Roboto,"Noto Sans KR",sans-serif}
.wrap{max-width:980px;margin:0 auto;padding:24px 16px}
h1{font-size:22px;margin:0 0 4px;color:#7fb4ff}
h2{font-size:16px;margin:26px 0 10px;color:#9ec5ff;border-bottom:1px solid #26406b;
 padding-bottom:6px}
.sub{color:#8aa0bf;font-size:13px;margin-bottom:18px}
.badge{display:inline-block;padding:2px 10px;border-radius:12px;font-size:12px;
 font-weight:600;margin-right:6px}
.b-done{background:#133a2a;color:#5fe0a8}.b-info{background:#102a4d;color:#7fb4ff}
.b-crit{background:#3a1320;color:#ff8da3}.b-high{background:#3a2713;color:#ffc27f}
.b-med{background:#2a2a13;color:#e8e07f}.b-low{background:#16233c;color:#9ec5ff}
.panel{background:#111c31;border:1px solid #26406b;border-radius:10px;
 padding:14px 16px;margin:10px 0}
table{width:100%;border-collapse:collapse;margin:6px 0}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #223a63}
th{color:#9ec5ff;font-size:12px;text-transform:uppercase;letter-spacing:.03em}
code{background:#0b1626;color:#bfe0ff;padding:1px 6px;border-radius:5px;
 font:13px/1.5 "JetBrains Mono",Consolas,monospace}
.flag{color:#5fe0a8;font-weight:700}
.muted{color:#8aa0bf}
a{color:#7fb4ff}
ul{margin:6px 0;padding-left:20px}
.kcol{color:#9ec5ff;width:120px}
.foot{margin-top:28px;color:#6880a0;font-size:12px;border-top:1px solid #26406b;
 padding-top:12px}
"""


def _esc(s) -> str:
    return html.escape(str(s), quote=True)


def _sev_class(sev: str) -> str:
    return {"critical": "b-crit", "high": "b-high",
            "medium": "b-med"}.get((sev or "").lower(), "b-low")


def _cwe_label(cwe_id: str) -> str:
    name = CWE_NAMES.get(cwe_id.upper(), "")
    return f"{cwe_id} ({name})" if name else cwe_id


def _html_ports(host) -> str:
    if not host or not host.open_ports:
        return "<p class='muted'>열린 포트 없음</p>"
    rows = ["<tr><th>포트</th><th>프로토콜</th><th>서비스</th><th>버전/배너</th></tr>"]
    for p in host.ports:
        if p.state == "open":
            rows.append(f"<tr><td><code>{p.port}</code></td><td>{_esc(p.proto)}</td>"
                        f"<td>{_esc(p.service or '-')}</td><td>{_esc(p.banner or '-')}</td></tr>")
    return "<table>" + "".join(rows) + "</table>"


def _html_vulns(report) -> str:
    if not (report.vuln_matches or report.detected_cve or report.detected_cwe):
        return "<p class='muted'>명시적 CVE/CWE 미탐지 — 수동 분석 필요</p>"
    out = []
    if report.detected_cve:
        out.append("<p><b>탐지 CVE</b>: " +
                   ", ".join(f"<code>{_esc(c)}</code>" for c in report.detected_cve) + "</p>")
    if report.detected_cwe:
        out.append("<p><b>탐지 CWE</b>: " +
                   ", ".join(_esc(_cwe_label(c)) for c in report.detected_cwe) + "</p>")
    for m in report.vuln_matches:
        ids = " ".join(m.cve + [_cwe_label(c) for c in m.cwe])
        badge = f"<span class='badge {_sev_class(m.severity)}'>{_esc(m.severity or 'info')}</span>"
        out.append(f"<div class='panel'>{badge}<b>{_esc(m.name)}</b> "
                   f"<span class='muted'>{_esc(ids)} — 매칭:{_esc(m.matched_on)}</span>"
                   + (f"<br><span class='muted'>{_esc(m.note)}</span>" if m.note else "")
                   + ("".join(f"<br>제안: <code>{_esc(s)}</code>" for s in m.suggest)) + "</div>")
    return "".join(out)


def _html_enriched(report) -> str:
    if not report.enriched:
        return "<p class='muted'>CVE 자동 수집 결과 없음(오프라인/비활성/미탐지)</p>"
    out = []
    for e in report.enriched:
        meta = " ".join(x for x in [e.severity, (f"CVSS {e.cvss}" if e.cvss else "")] if x)
        url = Enricher.cve_url(e.id)
        refs = "".join(f"<li><a href='{_esc(r)}'>{_esc(r)}</a></li>" for r in e.references[:3])
        pocs = "".join(f"<li><a href='{_esc(p)}'>{_esc(p)}</a></li>" for p in e.poc_repos[:3])
        out.append(
            f"<div class='panel'><b><a href='{_esc(url)}'>{_esc(e.id)}</a></b> "
            f"<span class='badge {_sev_class(e.severity)}'>{_esc(meta or 'n/a')}</span>"
            + (f"<br><span class='muted'>{_esc(e.description[:300])}</span>" if e.description else "")
            + (f"<br>CWE: {_esc(', '.join(_cwe_label(c) for c in e.cwe))}" if e.cwe else "")
            + (f"<br>참조:<ul>{refs}</ul>" if refs else "")
            + (f"공개 PoC:<ul>{pocs}</ul>" if pocs else "")
            + f"<span class='muted'>출처: {_esc(e.source)}</span></div>")
    return "".join(out)


def _html_flags(report) -> str:
    if report.flag_kind == "single":
        vals = [f.value for f in report.flags]
        return ("<p class='flag'>" + "  ".join(f"<code>{_esc(v)}</code>" for v in vals)
                + " ✅</p>") if vals else "<p class='muted'>플래그 미획득</p>"
    rows = []
    for kind, val in (("user", report.user_flag), ("root", report.root_flag)):
        if val:
            rows.append(f"<tr><td class='kcol'>{kind}.txt</td>"
                        f"<td class='flag'><code>{_esc(val)}</code> ✅</td></tr>")
        else:
            rows.append(f"<tr><td class='kcol'>{kind}.txt</td>"
                        f"<td class='muted'>미획득</td></tr>")
    return "<table>" + "".join(rows) + "</table>"


def _html_list(items) -> str:
    if not items:
        return "<p class='muted'>없음</p>"
    return "<ul>" + "".join(f"<li><code>{_esc(s)}</code></li>" for s in items) + "</ul>"


def _html_revshell(report) -> str:
    shells = getattr(report, "revshells", None)
    if not shells:
        return "<p class='muted'>공격자 IP 미확보 — 생략</p>"
    head = (f"<p class='muted'>LHOST={_esc(report.revshell_lhost)} "
            f"LPORT={report.revshell_lport} · 생성만, 권한 확인 대상에서 직접 실행</p>")
    rows = "".join(
        f"<li><b>{_esc(s.name)}</b>: <code>{_esc(s.payload)}</code></li>" for s in shells)
    return head + "<ul>" + rows + "</ul>"


def to_html(report, machine_name: str = "") -> str:
    prof = report.profile
    os_line = f"{prof.os_class.value} ({prof.tag}) · 확신도 {prof.confidence}%" if prof else "-"
    name = machine_name or report.target
    status_badge = ("b-done" if report.status == "done" else "b-info")
    gen = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!doctype html>
<html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ASSASSIN — {_esc(name)}</title>
<style>{_CSS}</style></head>
<body><div class="wrap">
<h1>ASSASSIN · {_esc(name)}</h1>
<div class="sub">
  <span class="badge {status_badge}">{_esc(report.status)}</span>
  <span class="badge b-info">{_esc(report.target)}</span>
  <span class="muted">OS: {_esc(os_line)} · 생성 {gen}</span>
</div>

<h2>포트 &amp; 서비스</h2>
{_html_ports(report.host)}

<h2>취약점 (CVE / CWE)</h2>
{_html_vulns(report)}

<h2>CVE 레퍼런스 (NVD / PoC)</h2>
{_html_enriched(report)}

<h2>플래그</h2>
{_html_flags(report)}

<h2>리버스쉘 (자동 준비 · 생성만, 실행 안 함)</h2>
{_html_revshell(report)}

<h2>수동 제안 (승인/입력 후 실행)</h2>
{_html_list(report.manual_suggestions)}

<div class="foot">자동 생성(ASSASSIN) · 관측·사용자 자료 기반 · 외부 라이트업 미참조 ·
권한이 확인된 대상 전용</div>
</div></body></html>
"""
