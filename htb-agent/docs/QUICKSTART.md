# ASSASSIN 빠른 시작 (1쪽)

> 권한이 확인된 대상(HTB·Dreamhack·CTF·인가된 진단)에서만 사용합니다. 자세한 내용은 [USAGE.md](USAGE.md).

## 1. 설치·점검 (처음 한 번)

```bash
cd htb-agent
pip install -e .                    # 'assassin' 명령 생성
sudo ./scripts/install_tools.sh     # 보안 도구 일괄 설치(Kali/Ubuntu)
assassin --doctor                   # 도구·VPN·LLM 준비 상태 점검 — 빨간 항목만 채우면 됨
```

## 2. 상황별 한 줄

| 하고 싶은 것 | 명령 |
|---|---|
| 처음 써 보기(위험한 것만 물어봄) | `assassin 10.129.1.5` |
| 모든 명령을 보며 배우기 | `assassin 10.129.1.5 --manual` |
| 해커톤: 최대 자율 + 시간 제한 | `assassin 10.129.1.5 --autonomous --time-budget 45 --writeup --html` |
| LLM 두뇌 붙이기(비용 상한) | `assassin 10.129.1.5 --llm hybrid --max-cost 2` |
| CTF/Dreamhack 문제 | `assassin chall.host:1337 --platform ctf --category web` |
| 중단한 곳부터 이어서 | 같은 명령 + `--resume` (Ctrl+C 로 멈춰도 저장됨) |
| 자격증명을 넣어 자동으로 채우기 | `--cred 사용자:비밀번호` |

## 3. 화면 읽는 법

| 표시 | 뜻 | 할 일 |
|---|---|---|
| `목적` | 이 명령이 무엇을 하려는지 | 읽고 이해 |
| `대안` | 더 안전한 2단계 방법(먼저 확인 → 실행) | 대안대로 해 보기 |
| `▲ 범위 밖` | 바인딩한 타겟 밖 주소 | 내 VPN IP 면 `--attacker-ip`, 아니면 엔터(건너뛰기) |
| `⟳ 앞서 실패한 같은 종류` | 같은 실패 반복 중 | 다른 도구·경로 고려 |
| `[y=실행 / 엔터=건너뛰기]` | 사람 확인 | `y` 실행, 엔터 건너뜀 |

## 4. 끝나면 볼 것

- **수동 제안(종류별)**: 자격증명 필요 → `--cred` 로 재실행 / 상한 초과 → `--max-enum` 또는 `--resume` / 실행 위험 → 적힌 대안대로.
- **결과물**: `--writeup`(라이트업) · `--html`(대시보드, 상단 '한눈에 보기') · `--json`.
- **실행 재생**: `assassin --replay state/audit_<타겟>.jsonl` → 단계별로 넘겨 보는 HTML.

## 5. 발표·연습

```bash
./scripts/showcase.sh            # 데모 + 성능 측정 + 재생 HTML + 대시보드를 한 번에(오프라인)
assassin --bench                 # 모의 문제 12개로 성공률 측정(규칙만)
assassin --bench --llm hybrid    # LLM 을 붙였을 때와 비교
```

## 6. 안전 경계 (바뀌지 않음)

모든 명령은 **검증 → 범위 → 승인** 3관문을 통과해야 실행됩니다. 리버스쉘·권한상승·크래킹 등은 **준비만** 하고 실행은 사람이 결정합니다. 막히면 [USAGE.md §17 트러블슈팅](USAGE.md).
