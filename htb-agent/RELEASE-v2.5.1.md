# ASSASSIN v2.5.1 — 릴리스 노트

- **버전**: 2.5.1
- **날짜**: 2026-10-09
- **대상 커밋**: `2e27891` (`claude/zen-goldberg-yma7t2`)
- **전체 변경 이력**: [`CHANGELOG.md`](./CHANGELOG.md) 참고

> 이 저장소는 egress 정책상 git 태그/GitHub Release 를 이 환경에서 생성할 수 없어,
> 릴리스 기록을 저장소 내 파일로 남긴다. 태그가 필요하면 `git tag -a v2.5.1 2e27891`
> 후 권한 있는 환경에서 `git push origin v2.5.1`.

---

## 🛠 수정 (Fixed)

- **자율학습 상태 오염(lateral 전제)** — `_acquire_knowledge` 가 학습 토픽을
  `world.loot` 에 적재해, 자격증명·발판이 없어도 lateral 단계 전제가 충족돼 투기적
  LLM 라운드를 소모하고 성장 지표를 왜곡하던 문제. 학습 지식을 `world.learned` 로
  분리하고(전제는 loot 만 참조), 성장 지문에는 learned 를 반영해 '학습→다음 스윕'
  흐름은 유지.
- **`--resume` 시 provenance 판정 손실** — 재개 시 flag 출처(verdict)를 재계산해
  `looked-up`(라이트업·학습 유래 의심)이 `exploit-derived` 로 승격되거나, 오프라인
  공략 플래그가 `local-derived` 로 강등되던 문제. 첫 실행의 판정을 상태에 보존·복원.
- **정찰 중 Ctrl+C** — 첫 포트스캔 도중 중단 시 raw 트레이스백 + 상태 유실로
  `--resume` 약속이 깨지던 문제. 정찰을 중단 처리로 감싸 상태 저장 후 정상 종료하고,
  최상위 진입점에 Ctrl+C·예외 가드 추가(전체 추적은 `ASSASSIN_DEBUG=1`).

## 🔒 안전 (Safety)

- **파괴적 명령 차단 확대** — 토큰 단위 검사 추가: `shred`·`wipefs`·`mkfs`족
  (`mke2fs`/`mkswap`/`mkfs.*`)·`find … -delete|-exec rm`·루트/홈 `chmod`·`chown -R`·
  디바이스/시스템경로 `dd`·`truncate`·리다이렉트 절단(`> /etc/…`). 디바이스 매칭을
  loop/dm-/md/sr/disk-by-id/mapper 로 확대. auto 모드에서 사람 확인 없이 실행되던
  fail-open 해소. 상대·작업공간 경로는 오탐 없이 통과.

## ➕ 추가 (Added)

- **`--max-llm`** — LLM 제안 명령 최대 개수 플래그(기본 5, 자율모드 8). 기존 config
  필드를 CLI 로 노출하고 자율 램프에 포함(다른 한계값과 대칭).

## 🔧 변경 (Changed)

- 소스 배포(sdist)에 `knowledge/`·`bench/`·문서 포함(`MANIFEST.in`). wheel 은 KB 를
  포함하지 않는다는 제약을 `pyproject.toml` 주석에 명확화(소스 트리 / `pip install -e .`
  / `--knowledge` 사용).

---

## ✅ 품질 지표

- 테스트 **78 스위트 / 2105 passed / 0 failed**
- **ruff·mypy 0건** · README CLI 옵션 표 최신 · 버전 4종(pyproject/`__init__`/CHANGELOG/`--version`) 일치

## 🛡 안전 불변식 (재검증, 전부 HOLD)

3-게이트(validate→scope→approve) · 생성전용 경계(revshell/privesc/crack/cloud) ·
provenance 순서(looked-up 우선) · KB 라이트업 차단 · 샌드박스 egress 컨테인먼트
(Docker/VM fail-closed).

## 📌 알려진 제약 (문서화, 의도적)

- VM `--vm-confine` ACCEPT 스캔은 filter 테이블 OUTPUT 체인 전용(`--noflush` 신뢰모델).
  `--vm-confine` 전에 기존 iptables 규칙 정리 권장.
- 타겟에서 수집한 자격증명은 설계상 플래너 LLM 으로 전달됨(Ollama 모드는 localhost
  유지). 세션 비밀(userEmail 등)은 전송하지 않음.
