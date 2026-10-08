# 실행: htb-agent 디렉토리에서  python3 tests/test_demo.py
# 데모 하네스 스모크: 네트워크 없이 전체 파이프라인이 끝까지 돌고 산출물이 나오는지.
import os
import sys
sys.path.insert(0, "src")
sys.path.insert(0, "scripts")
import demo  # noqa: E402
from htb_agent import ui  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

ui.set_color_enabled(False)

print("=== build_demo_report: 전체 파이프라인 무오류 ===")
rep = demo.build_demo_report()
check("타겟 바인딩", rep.target == demo.TARGET)
check("RECON 포트 탐지", rep.host is not None and len(rep.host.open_ports) >= 5)
check("OS 식별(windows_ad)", rep.profile is not None and rep.profile.os_class.value == "windows_ad")
check("취약점 매칭(vsftpd 등)", len(rep.vuln_matches) >= 1)
check("CVE 자동수집(오프라인 캔드)", len(rep.enriched) >= 1)
check("enrich 에 NVD 설명 존재", any(e.description for e in rep.enriched))
check("LLM 제안 반영", len(rep.llm_findings) >= 1)

print("\n=== summary / 라이트업 생성 ===")
s = rep.summary()
check("요약에 VULN 섹션", "VULN" in s or "취약점" in s)
check("요약에 CVE 레퍼런스", "CVE 레퍼런스" in s or "NVD" in s)

print("\n=== main(): 미리보기 모드 무오류 ===")
rc = demo.main([])
check("main 반환 0", rc == 0)

print("\n=== main(): --write 저장 ===")
out = os.path.join("/tmp", "assassin_demo_out")
rc = demo.main(["--write", out])
check("--write 반환 0", rc == 0)
check("HTB 라이트업 파일 생성", os.path.isfile(os.path.join(out, "demo_writeup_htb.md")))
check("Tistory 라이트업 파일 생성", os.path.isfile(os.path.join(out, "demo_writeup_tistory.md")))
with open(os.path.join(out, "demo_writeup_htb.md"), encoding="utf-8") as f:
    md = f.read()
check("라이트업에 CVE 레퍼런스 섹션", "CVE 레퍼런스" in md)
check("라이트업 순수 MD(HTML 없음)", "<div" not in md and "<span" not in md)

print("\n=== 라이브 데모: 3관문 시연 ===")
rep2, runner = demo.build_demo()
st = rep2.gate_stats
check("검토 대상 1건 이상 수동 강등", st["denied_review"] >= 1)
check("범위 밖 1건 이상 미실행", st["denied_scope"] >= 1)
check("실행 수 = 실제 러너 호출(정찰 제외)",
      st["executed"] == len([c for c in runner.calls if not c.startswith("nmap")]))
check("파이프→셸 명령 실제 실행 0", not any("| bash" in c for c in runner.calls))
check("범위 밖 주소 실제 실행 0", not any(demo.OUT_OF_SCOPE in c for c in runner.calls))
check("강등 명령이 수동 제안에 남음",
      any("| bash" in s and "실행위험" in s for s in rep2.manual_suggestions))
check("ANALYSIS 에 명령이 아닌 분석문", rep2.analysis.startswith("가설:"))

import contextlib  # noqa: E402
import io  # noqa: E402
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    rc = demo.main(["--live"])
live = buf.getvalue()
check("--live 반환 0", rc == 0)
check("7단계 모두 출력", all(f"STEP {i}." in live for i in range(1, 8)))
check("승인 화면 목적·대안 시연", "목적" in live and "대안" in live and "2단계" in live)
check("성능 측정 단계: 규칙만 해결 수·검증된 풀이율", "규칙만" in live and "검증된 풀이율" in live)
check("지식 단계: 시작 지식·승격·공유 흐름", "시작 지식" in live and "승격 발췌" in live and "공유 흐름" in live)
check("범위 밖 바인딩 거부 장면", "거부:" in live and "8.8.8.8" in live)
check("위험 명령 실행 0건 확인 문구", "실제 실행 0건" in live)
check("--pace 잘못된 값 → 2", demo.main(["--live", "--pace", "x"]) == 2)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
