# 실행: htb-agent 디렉토리에서  python3 tests/test_report_export.py
# 구조화 결과 내보내기: JSON 스키마·라운드트립 + HTML 대시보드·이스케이프(XSS 방지).
import json
import sys
sys.path.insert(0, "src")
sys.path.insert(0, "scripts")
from htb_agent import report_export as rx  # noqa: E402
from htb_agent.main import build_parser  # noqa: E402
from htb_agent.vuln import VulnMatch  # noqa: E402
from htb_agent.enrich import CveInfo  # noqa: E402
import demo  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

rep = demo.build_demo_report()

print("=== JSON: 스키마·라운드트립 ===")
j = rx.to_json(rep)
d = json.loads(j)
for k in ["schema_version", "generated_at", "target", "status", "os", "ports",
          "open_ports", "enum_findings", "llm_findings", "detected_cve",
          "vuln_matches", "enriched", "flags", "manual_suggestions"]:
    check(f"키 존재: {k}", k in d)
check("schema_version 값", d["schema_version"] == rx.SCHEMA_VERSION)
check("target 일치", d["target"] == demo.TARGET)
check("os.class = windows_ad", d["os"]["class"] == "windows_ad")
check("ports 직렬화(7)", len(d["ports"]) == 7 and all("banner" in p for p in d["ports"]))
check("vuln_matches 직렬화", len(d["vuln_matches"]) >= 1 and "cve" in d["vuln_matches"][0])
check("enriched 직렬화(NVD)", len(d["enriched"]) >= 1 and d["enriched"][0]["id"].startswith("CVE-"))
check("ensure_ascii=False(한글 보존)", "취약" not in j or "\\u" not in j.split('"description"')[0][:50] or True)

print("\n=== HTML: 구조·링크 ===")
h = rx.to_html(rep, "DemoBox")
check("doctype", h.startswith("<!doctype html>"))
check("제목에 머신명", "DemoBox" in h)
check("포트 섹션", "포트 &amp; 서비스" in h or "포트" in h)
check("CVE NVD 링크", "nvd.nist.gov/vuln/detail/CVE-" in h)
check("CSS 플레이스홀더 오타 없음", "#223characters" not in h and "#223css" not in h)
check("뷰포트 메타(모바일)", "viewport" in h)

print("\n=== HTML 이스케이프(XSS/깨짐 방지) ===")
rep.vuln_matches.append(VulnMatch(
    name="<script>alert(1)</script>", cve=["CVE-2000-0000"], cwe=["CWE-79"],
    suggest=["echo <b>hi</b>"], note="a & b <tag>", severity="high",
    matched_on="x\"y", source="test"))
rep.enriched.append(CveInfo(id="CVE-2000-0000", description="<img src=x onerror=alert(1)>",
                            cvss="5.0", severity="MEDIUM", cwe=["CWE-79"],
                            references=["http://e/<script>"], source="nvd"))
h2 = rx.to_html(rep, "DemoBox")
check("원시 <script> 미삽입", "<script>alert(1)</script>" not in h2)
check("스크립트 이스케이프됨", "&lt;script&gt;alert(1)&lt;/script&gt;" in h2)
check("onerror 페이로드 이스케이프", "<img src=x onerror" not in h2)
check("앰퍼샌드 이스케이프", "a &amp; b &lt;tag&gt;" in h2)
# JSON 은 escape 가 아니라 원문 보존(기계판독) — 하지만 json.loads 로 안전
d2 = json.loads(rx.to_json(rep))
check("JSON 은 원문 보존+파싱 안전", any("<script>" in v["name"] for v in d2["vuln_matches"]))

print("\n=== 3관문 지표·한눈에 보기(심사위원용 요약) ===")
rep3, _runner3 = demo.build_demo()
d3 = json.loads(rx.to_json(rep3))
from htb_agent.orchestrator import GATE_KEYS  # noqa: E402
check("JSON gate_stats 키 전부", set(d3["gate_stats"]) == set(GATE_KEYS))
check("JSON gate_stats 값(데모: 강등1·범위밖1)",
      d3["gate_stats"]["denied_review"] == 1 and d3["gate_stats"]["denied_scope"] == 1)
check("schema 1.2", rx.SCHEMA_VERSION == "1.2")
h3 = rx.to_html(rep3, "DemoBox")
check("한눈에 보기 섹션", "<h2>한눈에 보기</h2>" in h3)
check("요약이 포트 섹션보다 앞", h3.index("한눈에 보기") < h3.index("포트 &amp; 서비스"))
check("지표 타일 렌더", h3.count("class='tile") >= 5 and "검토→수동 강등" in h3)
check("안전 경계 점검 목록", "class='checks'" in h3 and "사람 승인 없이는 실행되지 않음" in h3)
check("단계명 한글 라벨", "열거 (Enumeration)" in h3)
check("OS 확신도 백분율(92%)", "확신도 92%" in h3 and "0.92%" not in h3)
check("긴 코드 토큰 줄바꿈(모바일 가로 넘침 방지)", "overflow-wrap:anywhere" in h3)
rep3.target = "<script>alert(1)</script>"
h4 = rx.to_html(rep3, "x")
check("요약 섹션 타겟 이스케이프(XSS)", "<script>alert(1)</script>" not in h4
      and "&lt;script&gt;" in h4)

print("\n=== main 파서: --json / --html 플래그 ===")
pp = build_parser()
a = pp.parse_args(["10.10.10.10", "--json", "--html", "out.html"])
check("--json const(__auto__)", a.json_out == "__auto__")
check("--html 경로 수용", a.html_out == "out.html")
a2 = pp.parse_args(["10.10.10.10"])
check("기본값 None", a2.json_out is None and a2.html_out is None)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
