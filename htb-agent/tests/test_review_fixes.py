# 실행: htb-agent 디렉토리에서  python3 tests/test_review_fixes.py
# 전체 검수(2026-10)에서 재현으로 확인한 결함 회귀 테스트 — 번호는 검수 보고서 항목 번호.
import json
import os
import sys
import tempfile
sys.path.insert(0, "src")
from htb_agent.observation.parsers import parse_http  # noqa: E402
from htb_agent.observation.web import parse_ffuf_json, parse_ffuf  # noqa: E402
from htb_agent.command_validator import validate  # noqa: E402
from htb_agent.config import Config, ConfigError, load_config  # noqa: E402
from htb_agent.knowledge import KnowledgeBase, Rule  # noqa: E402
from htb_agent.state import _pct  # noqa: E402
from htb_agent.scope_guard import ScopeGuard  # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput  # noqa: E402
from htb_agent.tools.recon import auto_approve_in_scope  # noqa: E402
from htb_agent.llm.fake_provider import FakeProvider  # noqa: E402
from htb_agent.llm.router import LLMRouter  # noqa: E402
from htb_agent.orchestrator import Orchestrator  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

def raises(fn, exc):
    try:
        fn()
    except exc:
        return True
    except Exception:
        return False
    return False

print("=== 1·2. parse_http: 빈 줄로 시작하는 구간 / 연속 빈 줄 ===")
r = parse_http("HTTP/1.1 301 Moved\r\nLocation: /a\r\n\r\n\r\nHTTP/1.1 200 OK\r\nServer: x\r\n\r\nbody")
check("빈 줄 3연속: 크래시 없이 최종 응답 200", r.status == 200 and r.headers.get("server") == "x")
r = parse_http("\n\n\nHTTP/1.1 200 OK\nServer: x\n\nbody")
check("앞쪽 공백 줄: 크래시 없이 200", r.status == 200)
r = parse_http("HTTP/1.1 301 M\r\n\r\n\r\n\r\nHTTP/1.1 200 OK\r\nServer: y\r\n\r\n<title>T</title>")
check("빈 줄 4연속: 빈 구간을 본문으로 오판하지 않음(최종 헤더·본문)",
      r.status == 200 and r.headers.get("server") == "y" and r.title == "T")
r = parse_http("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nServer: z\r\n\r\n<title>Q</title>")
check("기존 동작 유지: 100 Continue 체인", r.status == 200 and r.title == "Q")

print("\n=== 3. validate: 제어문자(NUL 등) ===")
v = validate("curl http://10.129.1.5/\x00x")
check("NUL 포함 → 예외 대신 오류 보고", not v.ok and any(i.code == "CONTROL_CHAR" for i in v.errors))
check("기타 C0 제어문자(\\x1b)도 거부", not validate("echo \x1b[31m").ok)
check("탭·개행은 정상 입력 유지", validate("echo a\tb").ok and validate("echo a\necho b").ok)

XML = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.129.1.5"/><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
</ports></host></nmaprun>"""
def _guard():
    g = ScopeGuard.from_cidr_strings(); g.bind_target("10.129.1.5"); return g
def _runner():
    return FakeRunner(lambda c: RunOutput(c, stdout=XML) if c.startswith("nmap")
                      else RunOutput(c, stdout="ok"))
def nul_llm(system, user, tier):
    if "분석가" in system:
        return "가설: 웹\n공격경로: 웹\n다음집중: 웹\n확신도: 하"
    return "curl http://{t}/\x00x\ncurl -s http://{t}/robots.txt"
try:
    rep = Orchestrator(_guard(), _runner(), KnowledgeBase(rules=[], notes=[]), auto_approve_in_scope,
                       llm_router=LLMRouter(FakeProvider(nul_llm)), max_rounds=1, max_sweeps=1,
                       phases=[("enum", "열거")], is_tool_available=lambda b: True).run()
    ok = True
except Exception:
    rep, ok = None, False
check("LLM 출력에 NUL 이 섞여도 세션이 끝까지 진행", ok and rep.status == "done")
check("NUL 명령은 검증 오류로 집계", ok and rep.gate_stats["rejected_validate"] >= 1)

print("\n=== 4. ffuf JSON: 예상 밖 구조 ===")
check("최상위 배열 → 크래시 없이 parse_error", parse_ffuf_json("[]").parse_error != "")
check("results: null → 크래시 없이 빈 결과", parse_ffuf_json('{"results": null}').entries == [])
check("비-dict 항목은 건너뜀",
      len(parse_ffuf_json('{"results": [1, "x", {"input": {"FUZZ": "admin"}, "status": 200}]}').entries) == 1)
check("input 이 비-dict 여도 크래시 없음",
      len(parse_ffuf_json('{"results": [{"input": "x", "url": "http://t/a", "status": 200}]}').entries) == 1)
check("parse_ffuf 디스패처도 크래시 없음", raises(lambda: parse_ffuf('{"results": null}'), Exception) is False)

print("\n=== 5~8. 설정 검증 ===")
check("5 문자열 숫자 → ConfigError", raises(lambda: Config.from_dict({"max_enum": "6"}), ConfigError))
check("5 bool 은 정수로 취급 안 함", raises(lambda: Config.from_dict({"max_rounds": True}), ConfigError))
check("6 allowed_ranges 단일 문자열 → 목록으로", Config.from_dict({"allowed_ranges": "10.129.0.0/16"})
      .allowed_ranges == ["10.129.0.0/16"])
check("6 목록 아닌 값(숫자) → ConfigError", raises(lambda: Config.from_dict({"attacker_ips": 5}), ConfigError))
check("7 지원 안 하는 backend → ConfigError",
      raises(lambda: Config.from_dict({"llm": {"backend": "gpt"}}), ConfigError))
check("7 지원 안 하는 tier → ConfigError", raises(lambda: Config.from_dict({"llm_tier": "max"}), ConfigError))
check("7 hybrid 는 허용", Config.from_dict({"llm": {"backend": "hybrid"}}).llm_backend == "hybrid")
c = Config.from_dict({"max_round": 9, "llm": {"backend": "none", "tiers": "x"}})
check("8 오타 키 → 경고(무시)", any("max_round" in w for w in c.warnings))
check("8 llm 하위 오타 키 → 경고", any("llm.tiers" in w for w in c.warnings))
check("정상 설정은 경고 없음", Config.from_dict({"max_enum": 6, "llm": {"backend": "claude"}}).warnings == [])
check("동봉 config.example.json 은 오류·경고 없이 로드", load_config("config/config.example.json").warnings == [])
check("from_dict 가 입력 dict 를 변형하지 않음",
      (lambda d: (Config.from_dict(d), d)[1])({"allowed_ranges": "10.1.0.0/16"})["allowed_ranges"]
      == "10.1.0.0/16")

print("\n=== 9. 가이드(note)만 있는 규칙 → LLM 컨텍스트에 가이드 전달 ===")
seen_user = []
def cap(system, user, tier):
    if "분석가" not in system:
        seen_user.append(user)
    return "가설: 웹\n공격경로: 웹\n다음집중: 웹\n확신도: 하" if "분석가" in system else ""
kb9 = KnowledgeBase(rules=[
    Rule("가이드전용규칙", [], ports=[80], note="GUIDE-TEXT " + "x" * 300),
    Rule("명령규칙", ["curl -i http://{t}/"], ports=[80], note="NOTE-NOT-NEEDED"),
], notes=[])
Orchestrator(_guard(), _runner(), kb9, auto_approve_in_scope, llm_router=LLMRouter(FakeProvider(cap)),
             max_rounds=1, max_sweeps=1, phases=[("enum", "열거")],
             is_tool_available=lambda b: True).run()
u = seen_user[0] if seen_user else ""
check("명령 없는 규칙: 가이드 앞부분이 전달됨", "가이드전용규칙: GUIDE-TEXT" in u)
check("가이드는 160자 + … 로 잘림", "x" * 200 not in u and "…" in u)
check("명령 있는 규칙: 기존처럼 명령만(note 미포함)", "명령규칙: curl -i" in u and "NOTE-NOT-NEEDED" not in u)

print("\n=== 10·11. KB 로더 경고 ===")
d = tempfile.mkdtemp(); rd = os.path.join(d, "rules"); os.makedirs(rd)
open(os.path.join(rd, "a_broken.json"), "w").write("{ not json")
json.dump([
    {"name": "정상", "suggest": ["curl http://{t}/"], "when": {"ports": [80]}},
    {"name": "포트오류", "suggest": ["x"], "when": {"ports": ["eighty"]}},
    {"name": "단계오류", "suggest": ["x"], "when": {"ports": [22]}, "phase": "privsec"},
    {"name": "조건없음", "suggest": [], "note": "guide"},
    {"name": "문자열suggest", "suggest": "curl x", "when": {"ports": [80]}},
    {"suggest": ["no name"]},
], open(os.path.join(rd, "b_rules.json"), "w"))
try:
    kbw = KnowledgeBase.load(d, include_seeds=False)
    loaded = True
except Exception:
    kbw, loaded = None, False
check("11 잘못된 포트 값이 있어도 로드 전체가 중단되지 않음", loaded)
names = [r.name for r in kbw.rules] if loaded else []
W = " | ".join(kbw.warnings) if loaded else ""
check("11 정상 규칙은 로드", "정상" in names)
check("11 깨진 JSON 파일 → 경고", "a_broken.json" in W)
check("11 포트 오류 규칙 → 건너뛰고 경고", "포트오류" not in names and "포트오류" in W)
check("11 문자열 suggest → 글자 분해 대신 건너뛰고 경고", "문자열suggest" not in names and "문자열suggest" in W)
check("11 name 없는 항목 → 경고", "name/suggest 없는 항목" in W)
check("11 알 수 없는 phase → 경고(로드는 유지)", "단계오류" in names and "privsec" in W)
check("10 조건 없는 규칙 → 보존 + 경고", "조건없음" in names and "조건없음" in W)
kb_real = KnowledgeBase.load("knowledge")
dead = sorted(w for w in kb_real.warnings if "when 조건 없음" in w)
check("10 불변식: 동봉 KB 경고는 조건 없는 규칙 4건뿐", len(kb_real.warnings) == 4 and len(dead) == 4)

print("\n=== 12~15. 경미 항목 ===")
check("12 저장 세션 확신도 0.92 → 92%", _pct(0.92) == "92%")
check("12 숫자 아님은 원값", _pct(None) == "None" and _pct("x") == "x")
check("13 YAML 예시 backend 설명에 hybrid", "hybrid" in open("config/config.example.yaml", encoding="utf-8").read())
check("14 approval 옵션 목록 '-w' 중복 없음",
      open("src/htb_agent/approval.py", encoding="utf-8").read().count('"-w"') == 1)
nd = tempfile.mkdtemp()
for sub in ("zz", "aa"):
    os.makedirs(os.path.join(nd, "notes", sub))
    open(os.path.join(nd, "notes", sub, "n.md"), "w").write(f"note-{sub}")
kn = KnowledgeBase.load(nd, include_seeds=False).notes
check("15 하위 디렉터리 노트 순서 결정적(이름순)", [n.split()[-1] for n in kn] == ["note-aa", "note-zz"])

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
