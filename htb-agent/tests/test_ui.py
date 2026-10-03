# 실행: htb-agent 디렉토리에서  python3 tests/test_ui.py
import sys
sys.path.insert(0, "src")
from htb_agent import ui

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== 색 비활성(테스트/파이프) ===")
ui.set_color_enabled(False)
check("paint 무색 원문", ui.paint("x", "accent") == "x")
check("accent 무색 원문", ui.accent("제목") == "제목")
check("banner 에 ANSI 없음", "\033[" not in ui.banner())
check("panel 에 ANSI 없음", "\033[" not in ui.panel("T", ["a", "b"]))

print("\n=== 색 활성 ===")
ui.set_color_enabled(True)
check("paint 색 적용", ui.paint("x", "accent").startswith("\033[") and ui.paint("x", "accent").endswith("\033[0m"))
check("strip_ansi 복원", ui.strip_ansi(ui.accent("abc")) == "abc")
check("banner 에 ANSI 있음", "\033[" in ui.banner())

print("\n=== 표시폭(전각/ANSI) ===")
check("ASCII 폭", ui.display_width("nmap") == 4)
check("한글 전각 폭2", ui.display_width("가나") == 4)
check("ANSI 제외 폭", ui.display_width(ui.accent("가나")) == 4)
check("혼합 폭", ui.display_width("ab가") == 4)

print("\n=== pad 정렬(표시폭 기준) ===")
check("ASCII 패딩", ui.pad("ab", 5) == "ab   ")
check("한글 패딩(전각 보정)", ui.display_width(ui.pad("가", 6)) == 6)
check("right 정렬", ui.pad("x", 4, "right") == "   x")
check("초과 시 원문", ui.pad("abcdef", 3) == "abcdef")

print("\n=== 레이아웃 요소 ===")
ui.set_color_enabled(False)
check("rule 제목 포함", "단계: 열거" in ui.rule("단계: 열거", 40))
check("panel 제목+내용 포함", "제목" in ui.panel("제목", ["내용"]) and "내용" in ui.panel("제목", ["내용"]))
check("heading 텍스트 포함", "VULN" in ui.heading("VULN", "🛑"))
check("kv 키·값 포함", "키" in ui.kv("키", "값", 6) and "값" in ui.kv("키", "값", 6))
check("bullet 텍스트 포함", "항목" in ui.bullet("항목"))
check("mark_ok 텍스트 포함", "준비됨" in ui.mark_ok("준비됨"))

# 박스 라인 폭 일관성(닫힘 보장)
ui.set_color_enabled(False)
p = ui.panel("환경", ["짧음", "조금 더 긴 라인입니다"]).splitlines()
widths = {ui.display_width(ln) for ln in p}
check("panel 모든 라인 동일 폭(닫힘)", len(widths) == 1)

print(f"\n결과: {passed} passed, {failed} failed")
ui.set_color_enabled(False)
sys.exit(1 if failed else 0)
