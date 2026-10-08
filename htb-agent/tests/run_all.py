#!/usr/bin/env python3
# 모든 테스트 스위트를 실행하고 집계. 실행: htb-agent 에서  python3 tests/run_all.py
import glob
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)   # htb-agent
SUITE_TIMEOUT = int(os.environ.get("ASSASSIN_TEST_SUITE_TIMEOUT", "300"))   # 스위트당 제한(초)
# 테스트는 실제 아웃바운드 네트워크를 쓰지 않는다(기본 fetcher 차단). 주입 fake fetcher 는 영향 없음.
os.environ.setdefault("ASSASSIN_NO_NET", "1")


def main() -> int:
    suites = sorted(f for f in glob.glob(os.path.join(HERE, "test_*.py")))
    total_pass = total_fail = failed_suites = 0
    for path in suites:
        name = os.path.basename(path)
        # stdin 을 /dev/null 로 — 대화형 승인(input())을 쓰는 테스트가 상속받은 stdin 에서
        # 블록하지 않고 즉시 EOF 를 받게 한다(비대화 실행·CI 안정성).
        try:
            r = subprocess.run([sys.executable, path], capture_output=True, text=True, cwd=ROOT,
                               stdin=subprocess.DEVNULL, timeout=SUITE_TIMEOUT)
        except subprocess.TimeoutExpired as e:
            print(f"  ⏱ {name:24} 제한시간 {SUITE_TIMEOUT}s 초과 — 실패 처리")
            print((e.stdout or "")[-800:] if isinstance(e.stdout, str) else "")
            failed_suites += 1
            continue
        last = ""
        for line in reversed(r.stdout.strip().splitlines()):
            if "passed" in line:
                last = line.strip()
                break
        print(f"  {'✅' if r.returncode == 0 else '❌'} {name:24} {last}")
        if r.returncode != 0:
            failed_suites += 1
            print(r.stdout[-800:]); print(r.stderr[-400:])
        # passed/failed 합산
        import re
        m = re.search(r"(\d+) passed, (\d+) failed", r.stdout)
        if m:
            total_pass += int(m.group(1)); total_fail += int(m.group(2))
    print(f"\n총 {len(suites)} 스위트 | {total_pass} passed, {total_fail} failed | "
          f"실패 스위트 {failed_suites}")
    return 1 if failed_suites else 0


if __name__ == "__main__":
    raise SystemExit(main())
