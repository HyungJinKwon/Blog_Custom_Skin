#!/usr/bin/env bash
# 발표용 원클릭 시연 — 네트워크·실도구 없이(가짜 대상) 전체 흐름과 산출물을 한 번에 만든다.
#   ① 라이브 데모(7단계: 범위 강제 → 정찰 → 열거 → 3관문 → 지식 → 산출 → 성능 측정)
#   ② 성능 측정(--bench, 오프라인 모의 문제 12개)
#   ③ 실행 재생 HTML(--replay) + 데모 리포트(JSON·HTML)·라이트업
# 사용: cd htb-agent && ./scripts/showcase.sh [출력폴더]   (기본 showcase_out)
#       PACE=2 ./scripts/showcase.sh   → 데모 단계 사이 2초 멈춤(발표 진행용)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-showcase_out}"
PACE="${PACE:-0}"
export PYTHONPATH="$HERE/src${PYTHONPATH:+:$PYTHONPATH}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

echo "▶ ① 라이브 데모"
python3 "$HERE/scripts/demo.py" --live --pace "$PACE"

echo
echo "▶ ② 성능 측정(오프라인 모의 문제 — 가짜 응답, 빠른 회귀)"
python3 -m htb_agent.main --bench --state-dir "$OUT/state" --knowledge "$HERE/knowledge"

echo
echo "▶ ②.5 라이브 성능 측정(실제 서비스 기동 + 진짜 도구 — loopback)"
echo "   (docker/vm 문제는 환경에 따라 자동 건너뜀. LLM 켜려면: --llm hybrid)"
ASSASSIN_NO_NET=1 python3 -m htb_agent.main --live-bench --state-dir "$OUT/state" \
    --knowledge "$HERE/knowledge" || echo "   (라이브 벤치 일부 생략 — 권한/도구 환경 확인)"

echo
echo "▶ ③ 산출물 생성"
python3 "$HERE/scripts/demo.py" --write "$OUT" >/dev/null
RUN_DIR="$(ls -d "$OUT"/state/bench/*/ | sort | tail -1)"
for trace in "$RUN_DIR"web-header_1.jsonl "$RUN_DIR"web-hidden-path_1.jsonl; do
    [ -f "$trace" ] && python3 -m htb_agent.main --replay "$trace"
done

echo
echo "✔ 완료 — 발표 때 열어 보세요:"
echo "  · 대시보드     : $OUT/demo_report.html  (상단 '한눈에 보기' + 가설 보드)"
echo "  · 실행 재생     : ${RUN_DIR}web-header_1.html  (←/→/스페이스)"
echo "  · 벤치 결과     : ${RUN_DIR}results.json  (오프라인) · $OUT/state/livebench/*/results.json (라이브)"
echo "  · 라이트업      : $OUT/demo_writeup_htb.md / demo_writeup_tistory.md"
echo
echo "다음 데모 포인트:"
echo "  · LLM 두뇌 연결(처음 한 번):  assassin --setup-llm   (이후 --llm 없이도 사용)"
echo "  · 완전자율 + 실제 익스플로잇: assassin <target> --autonomous --sandbox docker --llm hybrid"
echo "    (docker 없으면: --sandbox vm --vm-ssh user@kali-vm --vm-confine)"
echo "  · 환경 점검(초보자 첫 실행):  assassin --doctor"
