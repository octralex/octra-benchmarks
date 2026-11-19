#!/usr/bin/env bash
set -euo pipefail
base="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$base/build"
case "$(uname -s)" in
  Darwin)
    cxx="${CXX:-clang++}"
    inst="$base/build/openfhe-install"
    omp="$base/third-party/libomp/libomp/23.1.5"
    native_flag=-mcpu=native
    for source in pvac_bench pvac_wide; do
      "$cxx" -std=c++17 -O3 -g0 -Wall -Wextra -Werror "$native_flag" \
        '-DPVAC_COMPILER_FLAGS="-std=c++17 -O3 -g0 -mcpu=native"' \
        -I "$base/sources/pvac-include" "$base/$source.cpp" -o "$base/build/$source"
    done
    for source in openfhe_bench openfhe_wide; do
      "$cxx" -std=c++17 -O3 -g0 -Wall -Wextra "$native_flag" -DPARALLEL -DWITH_OPENMP \
        -Xpreprocessor -fopenmp -isystem "$omp/include" \
        -isystem "$inst/include/openfhe" -isystem "$inst/include/openfhe/pke" \
        -isystem "$inst/include/openfhe/core" -isystem "$inst/include/openfhe/binfhe" \
        -isystem "$inst/include/openfhe/third-party/cereal/include" \
        "$base/$source.cpp" -L "$inst/lib" -L "$omp/lib" \
        -lOPENFHEpke -lOPENFHEcore -lomp \
        -Wl,-rpath,"$inst/lib" -Wl,-rpath,"$omp/lib" \
        -o "$base/build/$source"
      codesign --sign - --force "$base/build/$source"
    done
    ;;
  Linux)
    cxx="${CXX:-g++}"
    inst="$base/build/openfhe-install-linux"
    native_flag=-march=native
    for source in pvac_bench pvac_wide; do
      "$cxx" -std=c++17 -O3 -g0 -Wall -Wextra -Werror "$native_flag" \
        '-DPVAC_COMPILER_FLAGS="-std=c++17 -O3 -g0 -march=native"' \
        -I "$base/sources/pvac-include" "$base/$source.cpp" -o "$base/build/$source"
    done
    for source in openfhe_bench openfhe_wide; do
      "$cxx" -std=c++17 -O3 -g0 -Wall -Wextra "$native_flag" -DPARALLEL -DWITH_OPENMP -fopenmp \
        -isystem "$inst/include/openfhe" -isystem "$inst/include/openfhe/pke" \
        -isystem "$inst/include/openfhe/core" -isystem "$inst/include/openfhe/binfhe" \
        -isystem "$inst/include/openfhe/third-party/cereal/include" \
        "$base/$source.cpp" -L "$inst/lib" \
        -lOPENFHEpke -lOPENFHEcore \
        -Wl,-rpath,"$inst/lib" \
        -o "$base/build/$source"
    done
    ;;
  *) echo "unsupported platform" >&2; exit 2 ;;
esac
