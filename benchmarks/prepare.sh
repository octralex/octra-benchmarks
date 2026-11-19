#!/usr/bin/env bash
set -euo pipefail
base="$(cd "$(dirname "$0")" && pwd)"
cd "$base"
case "$(uname -s)" in
  Darwin)
    for tool in uv cargo clang++ python3 git curl; do command -v "$tool" >/dev/null; done
    ;;
  Linux)
    for tool in cargo g++ cmake python3 git curl taskset readelf ldd objdump; do command -v "$tool" >/dev/null; done
    ;;
  *) echo "unsupported platform" >&2; exit 2 ;;
esac
bash fetch-sources.sh
if test "$(uname -s)" = Darwin; then
  if test ! -x .build-tools/bin/cmake; then
    uv venv .build-tools --python python3.11
    uv pip install --python .build-tools/bin/python 'cmake==4.4.5'
  fi
  uv pip freeze --python .build-tools/bin/python > build-tools-requirements.txt
else
  cmake --version > build-tools-requirements.txt
fi
python3 fixtures.py
bash build-openfhe.sh
bash build-native.sh
bash build-tfhe.sh
bash build-diagnostics.sh
bash build-parameters.sh
python3 manifest.py
