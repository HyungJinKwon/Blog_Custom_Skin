"""
Replay — 감사 로그(JSONL)를 단계별로 재생하는 HTML 뷰어
=====================================================

교육·심사 발표용. 실행 트랜스크립트(`state/audit_<타겟>.jsonl`, `--bench` 시도별 로그)를 읽어
'명령 제안 → 관문 결과 → 실행 결과'를 명령당 한 단계로 묶고, 분석·플래그·중단 등 주요 사건을
시간순 타임라인으로 보여준다. 이전/다음/자동 재생·키보드(←/→/스페이스)로 넘겨 본다.

로그 내용은 신뢰하지 않는 데이터로 다룬다 — JSON 으로 페이지에 싣고(`</` 이스케이프),
화면에는 textContent 로만 넣어 스크립트 주입이 불가능하다. 외부 의존 없음(단일 HTML).
"""
from __future__ import annotations

import json
from pathlib import Path

# 사건 종류 → (아이콘, 라벨, 강조 클래스)
_KIND = {
    "session_start": ("▶", "세션 시작", "info"),
    "resumed": ("↺", "재개 — 이전 결과 복원", "info"),
    "recon": ("📡", "정찰(포트 스캔)", "info"),
    "profile": ("🧭", "대상 식별", "info"),
    "analyst": ("🧠", "분석가 판단", "info"),
    "tier_escalate": ("⬆", "강력 모델로 승격", "warn"),
    "plan_update": ("🎯", "계획(가설 기록) 갱신", "info"),
    "hypothesis_signal": ("◎", "가설 대조", "dim"),
    "hypothesis_stuck": ("⚠", "가설 막힘 → 재계획 요청", "warn"),
    "knowledge_acquired": ("🎓", "지식 자동 학습", "ok"),
    "knowledge_gap": ("❔", "미해석 공백", "dim"),
    "cred_harvested": ("🔑", "자격증명 발견", "ok"),
    "hash_found": ("#", "해시 발견", "ok"),
    "flag_found": ("🚩", "플래그 획득", "flag"),
    "interrupted": ("■", "사용자 중단", "warn"),
    "timed_out": ("⏱", "시간 예산 소진", "warn"),
    "cost_capped": ("$", "LLM 비용 상한 도달", "warn"),
    "session_end": ("■", "세션 종료", "info"),
}
# 명령 단계의 결과 → (상태 라벨, 클래스)
_GATE = {
    "executed": ("실행됨", "ok"),
    "run_failed": ("실행 실패", "warn"),
    "skipped": ("건너뜀(도구 없음)", "dim"),
    "rejected": ("거부(검증/범위)", "warn"),
    "denied": ("미승인 → 수동 제안", "warn"),
}
_SKIP = {"session_end_marker", "diagnosis", "enriched", "vuln", "revshell_prepared",
         "cloud_prepared", "privesc_prepared", "crack_prepared"}


def load_events(path: str) -> list[dict]:
    """JSONL 을 읽는다(깨진 줄은 건너뜀)."""
    out: list[dict] = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if isinstance(rec, dict) and rec.get("event"):
                out.append(rec)
    return out


def _brief(rec: dict) -> str:
    e = rec.get("event")
    if e == "session_start":
        return f"타겟 {rec.get('target', '')}" + (" · 재개" if rec.get("resume") else "")
    if e == "recon":
        return f"상태 {rec.get('status', '')} · 열린 포트 {rec.get('open_ports', [])}"
    if e == "profile":
        return f"OS {rec.get('os', '')} · 확신도 {rec.get('confidence', '')}"
    if e == "flag_found":
        return f"{rec.get('kind', '')} — {rec.get('value', '')} · 출처 {rec.get('provenance', '')}"
    if e == "session_end":
        return f"{rec.get('status', '')} — {rec.get('message', '')}"
    if e == "cred_harvested":
        return f"사용자 {rec.get('user', '')}"
    if e in ("knowledge_acquired",):
        return str(rec.get("detail", ""))
    if e == "knowledge_gap":
        return str(rec.get("term", ""))
    if e == "timed_out":
        return f"예산 {rec.get('budget_min', '')}분 · 경과 {rec.get('elapsed_sec', '')}초"
    if e == "plan_update":
        return f"갱신 {rec.get('revision', '')}회차"
    if e == "hypothesis_signal":
        res = {"hit": "신호 일치〔추정〕", "miss": "불일치"}.get(str(rec.get("result")), "")
        return f"{rec.get('hypothesis', '')} {res} · 상태 {rec.get('status', '')}"
    if e == "hypothesis_stuck":
        return f"{rec.get('hypothesis', '')} 연속 불일치 {rec.get('misses', '')}회"
    if e == "tier_escalate":
        return f"사유 {rec.get('reason', '')} · 단계 {rec.get('phase', '')}"
    return ""


def build_steps(events: list[dict]) -> list[dict]:
    """사건 목록 → 화면 단계. 명령은 제안~결과를 한 단계로 묶는다."""
    steps: list[dict] = []
    open_cmd: dict[str, dict] = {}
    for rec in events:
        e = rec.get("event", "")
        ts = str(rec.get("ts", ""))
        if e in _SKIP:
            continue
        if e == "proposed":
            st = {"ts": ts, "type": "command", "icon": "▸", "label": "명령 제안",
                  "cls": "info", "cmd": str(rec.get("cmd", "")), "phase": str(rec.get("phase", "")),
                  "status": "관문 대기", "detail": ""}
            steps.append(st)
            open_cmd[st["cmd"]] = st
            continue
        if e in ("executed", "skipped", "rejected", "denied") and rec.get("cmd") in open_cmd:
            st = open_cmd.pop(str(rec.get("cmd")))
            key = "run_failed" if (e == "executed" and not rec.get("launched", True)) else e
            st["status"], st["cls"] = _GATE[key]
            if e == "executed":
                st["detail"] = str(rec.get("summary") or rec.get("error") or "")
                if rec.get("returncode") not in (None, 0):
                    st["status"] += f" (종료코드 {rec.get('returncode')})"
            elif e == "rejected":
                st["detail"] = "; ".join(map(str, rec.get("errors") or [])) or str(rec.get("reason", ""))
            elif e == "denied":
                st["detail"] = ("검토 필요: " + "; ".join(map(str, rec.get("review") or []))
                                if rec.get("review") else "범위 밖 또는 사용자 거부")
            elif e == "skipped":
                st["detail"] = f"'{rec.get('binary', '')}' 미설치"
            continue
        icon, label, cls = _KIND.get(e, ("·", e, "dim"))
        detail = str(rec.get("text", "")) if e == "analyst" else ""
        if e == "plan_update":
            detail = "\n".join(map(str, rec.get("board") or []))
        steps.append({"ts": ts, "type": "event", "icon": icon, "label": label, "cls": cls,
                      "cmd": "", "phase": str(rec.get("phase", "")), "status": _brief(rec),
                      "detail": detail})
    return steps


_PAGE = """<!doctype html>
<html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ASSASSIN 재생 — __TITLE__</title>
<style>
:root{--bg:#0b1220;--panel:#111c31;--line:#26406b;--fg:#dce6f5;--dim:#8aa0bf;--acc:#7fb4ff;
 --ok:#5fe0a8;--warn:#ffc27f;--flag:#ff8da3}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
 font:14px/1.6 -apple-system,"Segoe UI",Roboto,"Noto Sans KR",sans-serif}
header{position:sticky;top:0;background:#0d1729;border-bottom:1px solid var(--line);
 padding:10px 16px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;z-index:2}
h1{font-size:16px;margin:0 12px 0 0;color:var(--acc)}
button{background:#16274a;color:var(--fg);border:1px solid var(--line);border-radius:8px;
 padding:6px 12px;font:inherit;cursor:pointer}button:hover{border-color:var(--acc)}
#pos{color:var(--dim);font-size:13px}
input[type=range]{flex:1;min-width:120px;accent-color:var(--acc)}
main{display:grid;grid-template-columns:minmax(220px,340px) 1fr;gap:14px;padding:14px 16px;
 max-width:1200px;margin:0 auto}
@media (max-width:760px){main{grid-template-columns:1fr}}
#list{max-height:calc(100vh - 90px);overflow:auto;border:1px solid var(--line);border-radius:10px;
 background:var(--panel)}
.item{padding:7px 10px;border-bottom:1px solid #1c2f52;cursor:pointer;font-size:13px;
 overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.item.cur{background:#1a3159;outline:1px solid var(--acc)}
.item.future{opacity:.45}
.ok{color:var(--ok)}.warn{color:var(--warn)}.flag{color:var(--flag);font-weight:700}
.dim{color:var(--dim)}.info{color:var(--acc)}
#card{border:1px solid var(--line);border-radius:10px;background:var(--panel);padding:16px}
#card h2{margin:0 0 6px;font-size:17px}
.meta{color:var(--dim);font-size:12px;margin-bottom:10px}
code{display:block;background:#0b1626;color:#bfe0ff;padding:10px;border-radius:8px;
 font:13px/1.5 "JetBrains Mono",Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere}
pre{background:#0b1626;border:1px solid #223a63;border-radius:8px;padding:10px;
 white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.6 "JetBrains Mono",Consolas,monospace}
.badge{display:inline-block;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600;
 background:#16274a;margin-right:6px}
.foot{color:var(--dim);font-size:12px;margin-top:12px}
</style></head><body>
<header>
 <h1>ASSASSIN 재생 · __TITLE__</h1>
 <button id="prev" title="이전 (←)">◀ 이전</button>
 <button id="play" title="재생/정지 (스페이스)">▶ 재생</button>
 <button id="next" title="다음 (→)">다음 ▶</button>
 <input id="seek" type="range" min="0" value="0" aria-label="단계 이동">
 <span id="pos"></span>
</header>
<main><div id="list" role="listbox" aria-label="단계 목록"></div>
<section id="card" aria-live="polite"></section></main>
<script id="data" type="application/json">__DATA__</script>
<script>
(function(){
 var S=JSON.parse(document.getElementById('data').textContent),i=0,timer=null;
 var list=document.getElementById('list'),card=document.getElementById('card'),
     seek=document.getElementById('seek'),pos=document.getElementById('pos'),
     play=document.getElementById('play');
 function el(t,c,txt){var e=document.createElement(t);if(c)e.className=c;
   if(txt!==undefined)e.textContent=txt;return e;}
 S.forEach(function(s,k){var it=el('div','item');
   it.appendChild(el('span',s.cls,s.icon+' '));
   it.appendChild(document.createTextNode(s.cmd||s.label));
   it.onclick=function(){go(k)};list.appendChild(it);});
 seek.max=Math.max(0,S.length-1);
 function go(k){if(!S.length){card.textContent='기록된 단계가 없습니다.';return;}
   i=Math.max(0,Math.min(S.length-1,k));var s=S[i];
   card.textContent='';
   var h=el('h2',s.cls,s.icon+' '+s.label);card.appendChild(h);
   card.appendChild(el('div','meta',(s.ts||'')+(s.phase?'  ·  단계 '+s.phase:'')));
   if(s.cmd){card.appendChild(el('code',null,'$ '+s.cmd));}
   if(s.status){var b=el('p');b.appendChild(el('span','badge '+s.cls,s.status));card.appendChild(b);}
   if(s.detail){card.appendChild(el('pre',null,s.detail));}
   var items=list.children;for(var k2=0;k2<items.length;k2++){
     items[k2].classList.toggle('cur',k2===i);items[k2].classList.toggle('future',k2>i);}
   items[i].scrollIntoView({block:'nearest'});
   seek.value=i;pos.textContent=(i+1)+' / '+S.length;}
 function toggle(){if(timer){clearInterval(timer);timer=null;play.textContent='▶ 재생';return;}
   play.textContent='■ 정지';timer=setInterval(function(){if(i>=S.length-1){toggle();return;}go(i+1);},1200);}
 document.getElementById('prev').onclick=function(){go(i-1)};
 document.getElementById('next').onclick=function(){go(i+1)};
 play.onclick=toggle;seek.oninput=function(){go(+seek.value)};
 document.addEventListener('keydown',function(e){if(e.key==='ArrowRight')go(i+1);
   else if(e.key==='ArrowLeft')go(i-1);else if(e.key===' '){e.preventDefault();toggle();}});
 go(0);
})();
</script>
<div class="foot" style="padding:0 16px 16px">ASSASSIN 실행 기록 재생 · 감사 로그 기반 · 권한이 확인된 대상 전용</div>
</body></html>
"""


def _json_for_script(obj) -> str:
    """<script> 안에 안전하게 싣는 JSON — `</script>`·`<!--` 로 빠져나갈 수 없게 이스케이프."""
    s = json.dumps(obj, ensure_ascii=False)
    return s.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def render_html(steps: list[dict], title: str = "") -> str:
    return (_PAGE.replace("__TITLE__", _esc(title or "실행 기록"))
            .replace("__DATA__", _json_for_script(steps)))


def replay_file(path: str, out: str | None = None) -> tuple[str, int]:
    """JSONL → HTML 파일. (출력 경로, 단계 수)"""
    steps = build_steps(load_events(path))
    out = out or str(Path(path).with_suffix(".html"))
    Path(out).write_text(render_html(steps, Path(path).stem), encoding="utf-8")
    return out, len(steps)
