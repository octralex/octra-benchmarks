#!/usr/bin/env bash
set -euo pipefail
base="$(cd "$(dirname "$0")" && pwd)"
export RUSTFLAGS='-C target-cpu=native'
cd "$base/tfhe-harness"
if test "${1:-}" = '--regenerate-lockfile'; then
  cargo generate-lockfile
fi
if python3 ../platform_support.py --tfhe-avx512-only 2>/dev/null; then
  cargo build --release --locked --jobs "${BUILD_JOBS:-2}" --features avx512
else
  cargo build --release --locked --jobs "${BUILD_JOBS:-2}"
fi
