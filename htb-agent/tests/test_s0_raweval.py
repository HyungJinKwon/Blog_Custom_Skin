# 실행: htb-agent 디렉토리에서  python3 tests/test_s0_raweval.py
#
# S0 — capture≠evaluate 구조 버그 교정 검증:
#   (1) set_web_app 가 write-once 고착이 아니라 '더 구체적 버전으로 보강'.
#   (2) 핑거프린트/searchsploit 매칭이 '요약'이 아니라 '원본(raw_output)'에서 수행 →
#       요약 손실(parse_http 엄격 정규식·searchsploit 12행 캡)로 버전/매칭이 사라지지 않음.
import sys
sys.path.insert(0, "src")
from htb_agent.world import WorldModel, _more_specific_version  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== _more_specific_version ===")
check("빈 기존 → 새 값 채택", _more_specific_version("16.0.40.7", ""))
check("거친→구체 보강(16 → 16.0.40.7)", _more_specific_version("16.0.40.7", "16"))
check("역방향 거부(16.0.40.7 → 16)", not _more_specific_version("16", "16.0.40.7"))
check("무관 값 거부(7.4.16 vs 16.0.40.7)", not _more_specific_version("7.4.16", "16.0.40.7"))
check("동일 값 거부", not _more_specific_version("16.0", "16.0"))

print("\n=== set_web_app (고착 해소) ===")
w = WorldModel(target="t")
w.set_web_app("freepbx", "")          # 제품만, 버전 미상
check("제품 고정", w.web_product == "freepbx")
check("버전 아직 빔", w.web_version == "")
w.set_web_app("freepbx", "16")        # 거친 버전
check("거친 버전 채택", w.web_version == "16")
w.set_web_app("freepbx", "16.0.40.7") # 더 구체 → 보강돼야 함(과거엔 고착되어 무시됨)
check("구체 버전으로 보강(고착 해소)", w.web_version == "16.0.40.7")
w.set_web_app("freepbx", "16")        # 역방향은 무시
check("역방향 무시(구체 유지)", w.web_version == "16.0.40.7")

print("\n=== 핑거프린트: 원본에서 수행(요약 손실 우회) ===")
# 요약기가 버렸을 법한 형태(개행 포함·긴 간격)의 FreePBX 버전이 raw 본문에만 있어도 식별되는지.
from htb_agent.vuln import fingerprint_webapp  # noqa: E402
raw_body = ('<!DOCTYPE html><html><head><title>FreePBX Administration</title>\n'
            'var FreePBX = {};\nappname "FreePBX"\n   16.0.40.7 \n</head></html>')
prod, ver = fingerprint_webapp(raw_body)
check("원본 본문에서 FreePBX 식별", prod == "freepbx")

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
