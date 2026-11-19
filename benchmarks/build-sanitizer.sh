#!/usr/bin/env bash
set -euo pipefail
base="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$base/build"
case "$(uname -s)" in
  Darwin) cxx="${CXX:-clang++}" ;;
  Linux) cxx="${CXX:-g++}" ;;
  *) echo "unsupported platform" >&2; exit 2 ;;
esac
"$cxx" -std=c++17 -O1 -g -Wall -Wextra -Werror -fsanitize=undefined -fno-sanitize-recover=undefined \
  "$base/wide_integer_sanitizer.cpp" -o "$base/build/wide_integer_sanitizer"
"$base/build/wide_integer_sanitizer" > "$base/results/wide-integer-sanitizer.jsonl"
