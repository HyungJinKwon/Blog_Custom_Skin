#!/bin/sh
# 인증 없는 Redis 기동 → 플래그 키 주입 → 같은 서버를 포그라운드로 유지
set -e
redis-server --bind 0.0.0.0 --protected-mode no --save '' --appendonly no &
SRV=$!
for i in $(seq 1 30); do redis-cli ping >/dev/null 2>&1 && break; sleep 0.3; done
redis-cli set flag "$(cat /flag.txt)" >/dev/null
wait "$SRV"
