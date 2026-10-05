# 실행: htb-agent 디렉토리에서  python3 tests/test_revshell.py
# 리버스쉘 생성기 + AWS/S3 지식 배선.
import io
import json
import sys
from contextlib import redirect_stdout, redirect_stderr
sys.path.insert(0, "src")
from htb_agent import ui, revshell
from htb_agent.main import build_parser, main
from htb_agent.knowledge import KnowledgeBase

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

ui.set_color_enabled(False)

print("=== parse_target ===")
check("IP:PORT", revshell.parse_target("10.10.14.5:4444") == ("10.10.14.5", 4444))
check("PORT + 기본호스트", revshell.parse_target("9001", "10.10.14.9") == ("10.10.14.9", 9001))
for bad in ["badport:xx", "1.2.3.4:0", "1.2.3.4:70000"]:
    try:
        revshell.parse_target(bad); check(f"거부: {bad}", False)
    except ValueError:
        check(f"거부: {bad}", True)
try:
    revshell.parse_target("4444"); check("호스트 없음 거부", False)
except ValueError:
    check("호스트 없음 거부", True)

print("\n=== generate: 페이로드 치환·안전 ===")
sh = revshell.generate("10.10.14.5", 4444)
check("여러 경우의 수(>=10)", len(sh) >= 10)
check("bash 페이로드 치환", any("/dev/tcp/10.10.14.5/4444" in s.payload for s in sh))
check("python3 포함", any(s.name == "python3" and "10.10.14.5" in s.payload for s in sh))
check("powershell 포함", any("powershell" in s.name for s in sh))
check("플레이스홀더 잔여 없음", not any("{ip}" in s.payload or "{port}" in s.payload for s in sh))
# format-escape 아티팩트({{·}}로 렌더되는 버그) 방지 + 중괄호 균형
def _balanced(p):
    bal = 0
    for ch in p:
        bal += 1 if ch == "{" else (-1 if ch == "}" else 0)
        if bal < 0:
            return False
    return bal == 0
check("중괄호 균형(awk/powershell 등)", all(_balanced(s.payload) for s in sh))
check("only 필터", [s.name for s in revshell.generate("1.2.3.4", 9, only=["bash -i"])] == ["bash -i"])
check("리스너 힌트 포트 반영", any("4444" in h for h in revshell.listener_hints(4444)))

print("\n=== LHOST 셸 메타문자 거부(인젝션 방지) ===")
for bad in ["1.2.3.4;id", "$(whoami)", "a b"]:
    try:
        revshell.generate(bad, 4444); check(f"거부: {bad}", False)
    except ValueError:
        check(f"거부: {bad}", True)

print("\n=== --revshell CLI ===")
pp = build_parser()
a = pp.parse_args(["--revshell", "10.10.14.5:4444"])
check("--revshell 파싱(target 선택적)", a.revshell == "10.10.14.5:4444" and a.target is None)
buf = io.StringIO()
with redirect_stdout(buf):
    code = main(["--revshell", "10.10.14.5:4444"])
out = buf.getvalue()
check("종료코드 0", code == 0)
check("리스너 출력", "nc -lvnp 4444" in out)
check("페이로드 출력", "/dev/tcp/10.10.14.5/4444" in out)
check("실행 안 함 명시", "실행" in out)
# 잘못된 입력 → 에러 종료
err = io.StringIO()
with redirect_stdout(io.StringIO()), redirect_stderr(err):
    code = main(["--revshell", "nope:xx"])
check("잘못된 입력 종료코드 2", code == 2)

print("\n=== AWS/S3 지식 로드·매칭 ===")
kb = KnowledgeBase.load("knowledge")
recs = kb.query("linux", [80], ["http"], phase="enum")
names = [r.rule_name for r in recs]
check("S3 비인증 열거 규칙 로드", any("S3 버킷 비인증" in n for n in names))
check("AWS 자격증명 규칙 로드", any("AWS 자격증명 식별" in n for n in names))
# {bucket} 등 플레이스홀더 → 수동(자동실행 아님)
s3 = next(r for r in recs if "S3 버킷 비인증" in r.rule_name)
auto = [kb.format_suggestion(t, "10.10.10.10")[1] for t in s3.suggestions]
check("S3 제안은 수동(플레이스홀더)", not all(auto))  # {bucket} 있는 건 False
# JSON 유효
json.load(open("knowledge/rules/cloud-aws.json", encoding="utf-8"))
check("cloud-aws.json 유효", True)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
