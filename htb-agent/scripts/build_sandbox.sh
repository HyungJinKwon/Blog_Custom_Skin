#!/usr/bin/env bash
# ASSASSIN 샌드박스 이미지 빌드 — 완전자율(--autonomous --sandbox docker)용
# 사용: ./scripts/build_sandbox.sh [이미지태그]   (기본 assassin-sandbox:latest)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAG="${1:-assassin-sandbox:latest}"

if ! command -v docker >/dev/null 2>&1; then
    echo "docker 가 설치되어 있지 않습니다. 먼저 Docker 를 설치하세요." >&2
    exit 1
fi

echo "[*] 샌드박스 이미지 빌드: ${TAG}"
docker build -t "${TAG}" "${HERE}/sandbox"

echo "[*] 완료. 사용 예:"
echo "    assassin <타겟> --autonomous --sandbox docker --llm hybrid"
