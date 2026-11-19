#!/usr/bin/env bash
set -euo pipefail
base="$(cd "$(dirname "$0")" && pwd)"
case "$(uname -s)" in
  Darwin)
    cxx="${CXX:-clang++}"
    inst="$base/build/openfhe-install"
    omp="$base/third-party/libomp/libomp/23.1.5"
    "$cxx" -std=c++17 -O3 -g0 -Wall -Wextra -mcpu=native -DPARALLEL -DWITH_OPENMP \
      -Xpreprocessor -fopenmp -isystem "$omp/include" \
      -isystem "$inst/include/openfhe" -isystem "$inst/include/openfhe/pke" \
      -isystem "$inst/include/openfhe/core" -isystem "$inst/include/openfhe/binfhe" \
      -isystem "$inst/include/openfhe/third-party/cereal/include" \
      "$base/openfhe_diagnostics.cpp" -L "$inst/lib" -L "$omp/lib" \
      -lOPENFHEpke -lOPENFHEcore -lomp \
      -Wl,-rpath,"$inst/lib" -Wl,-rpath,"$omp/lib" \
      -o "$base/build/openfhe_diagnostics"
    codesign --sign - --force "$base/build/openfhe_diagnostics"
    ;;
  Linux)
    cxx="${CXX:-g++}"
    inst="$base/build/openfhe-install-linux"
    "$cxx" -std=c++17 -O3 -g0 -Wall -Wextra -march=native -DPARALLEL -DWITH_OPENMP -fopenmp \
      -isystem "$inst/include/openfhe" -isystem "$inst/include/openfhe/pke" \
      -isystem "$inst/include/openfhe/core" -isystem "$inst/include/openfhe/binfhe" \
      -isystem "$inst/include/openfhe/third-party/cereal/include" \
      "$base/openfhe_diagnostics.cpp" -L "$inst/lib" \
      -lOPENFHEpke -lOPENFHEcore \
      -Wl,-rpath,"$inst/lib" \
      -o "$base/build/openfhe_diagnostics"
    ;;
  *) echo "unsupported platform" >&2; exit 2 ;;
esac
