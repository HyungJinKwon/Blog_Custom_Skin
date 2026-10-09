# 실행: htb-agent 디렉토리에서  python3 tests/test_growth_update.py
# 성장형+최신화 아키텍처(G1 성장 공유·G2 역량 등급·G3 통합 업데이트·G4 KB 버전) 회귀.
import os
import sys
import tempfile

sys.path.insert(0, "src")

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== G1: variant_stats 병합(성장 공유) ===")
from htb_agent.variant_stats import VariantStats
a = VariantStats()
a.record("ffuf", "-mc 200", True); a.record("ffuf", "-mc 200", False)   # succ1/att2
b = VariantStats()
b.record("ffuf", "-mc 200", True); b.record("nmap", "-sV", True)        # succ1/att1 · succ1/att1
n = a.merge(b)
k = VariantStats._key("ffuf", "-mc 200")
check("병합 키 수", n == 2)
check("같은 키 succ/att 합산", a.stats[k]["succ"] == 2 and a.stats[k]["att"] == 3)
check("새 키 유입", VariantStats._key("nmap", "-sV") in a.stats)
# 공유 안전성: 통계에는 binary+fragment 만(타겟·명령전체·출력 없음)
check("통계 키에 타겟/전체명령 없음", all("\x1f" in kk and " " not in kk.split("\x1f")[0]
                                      for kk in a.stats))

print("\n=== G1: export/import 라운드트립 ===")
with tempfile.TemporaryDirectory() as d:
    p = os.path.join(d, "share.json")
    a.save(p)
    c = VariantStats.load(p)
    check("export→load 라운드트립", c.stats == a.stats)

print("\n=== G2: 역량 등급 ===")
from htb_agent.doctor import _capability_grade
g_full, _ = _capability_grade(strong_llm=True, any_llm=True, essentials_ok=True, sandbox_ok=True)
g_std, _ = _capability_grade(strong_llm=False, any_llm=True, essentials_ok=False, sandbox_ok=False)
g_std2, _ = _capability_grade(strong_llm=False, any_llm=False, essentials_ok=True, sandbox_ok=False)
g_base, tips = _capability_grade(strong_llm=False, any_llm=False, essentials_ok=False, sandbox_ok=False)
check("full = 강력LLM+도구+샌드박스", g_full == "full")
check("standard = LLM 있음", g_std == "standard")
check("standard = 도구 있음", g_std2 == "standard")
check("baseline = 둘 다 없음", g_base == "baseline" and len(tips) >= 2)

print("\n=== G4: KB 버전 상수 ===")
from htb_agent.knowledge import KB_VERSION
check("KB_VERSION 노출", isinstance(KB_VERSION, str) and KB_VERSION)

print("\n=== G3: --update 오프라인은 네트워크 생략(안전) ===")
from htb_agent import main as M
class _A:  # 최소 args 더미
    offline = True
rc = M._run_update(_A(), None, "knowledge")
check("--update --offline rc=0(무작업)", rc == 0)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
