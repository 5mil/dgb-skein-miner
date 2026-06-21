#!/usr/bin/env bash
# dgb-skein-miner launcher (Linux / macOS)
# Edit config.json or pass flags directly
set -e

BIN="./miner"

if [ ! -f "$BIN" ]; then
  echo "[dgb-skein-miner] Binary not found. Build with: ucm compile .main ./miner"
  exit 1
fi

exec "$BIN" --config-file config.json "$@"
