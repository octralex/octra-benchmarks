#!/usr/bin/env bash
set -euo pipefail
base="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$base/build" "$base/results"
case "$(uname -s)" in
  Darwin) cxx="${CXX:-clang++}"; native_flag=-mcpu=native ;;
  Linux) cxx="${CXX:-g++}"; native_flag=-march=native ;;
  *) echo "unsupported platform" >&2; exit 2 ;;
esac
"$cxx" -std=c++17 -O3 -g0 -Wall -Wextra -Werror "$native_flag" \
  "-DPVAC_COMPILER_FLAGS=\"-std=c++17 -O3 -g0 $native_flag\"" \
  -I "$base/sources/pvac-include" "$base/pvac_parameters.cpp" -o "$base/build/pvac_parameters"
"$base/build/pvac_parameters" --output "$base/results/pvac-parameters.json"
