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

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
