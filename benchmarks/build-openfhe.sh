#!/usr/bin/env bash
set -euo pipefail
base="$(cd "$(dirname "$0")" && pwd)"
src="$base/openfhe-git"
case "$(uname -s)" in
  Darwin)
    cmake="$base/.build-tools/bin/cmake"
    bld="$base/build/openfhe-macos"
    inst="$base/build/openfhe-install"
    omp="$base/third-party/libomp/libomp/23.1.5"
    install_name_tool -id "$omp/lib/libomp.dylib" "$omp/lib/libomp.dylib"
    codesign --sign - --force "$omp/lib/libomp.dylib"
    "$cmake" -S "$src" -B "$bld" \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX="$inst" \
      -DCMAKE_C_FLAGS="-I$omp/include" \
      -DCMAKE_CXX_FLAGS="-I$omp/include" \
      -DCMAKE_SHARED_LINKER_FLAGS="-L$omp/lib" \
      -DCMAKE_EXE_LINKER_FLAGS="-L$omp/lib" \
      -DOpenMP_CXX_FLAGS="-Xpreprocessor -fopenmp -I$omp/include" \
      -DOpenMP_CXX_LIB_NAMES=omp \
      -DOpenMP_omp_LIBRARY="$omp/lib/libomp.dylib" \
      -DNATIVE_SIZE=64 \
      -DWITH_NATIVEOPT=ON \
      -DWITH_OPENMP=ON \
      -DBUILD_UNITTESTS=OFF \
      -DBUILD_EXAMPLES=OFF \
      -DBUILD_BENCHMARKS=OFF
    ;;
  Linux)
    cmake="${CMAKE:-cmake}"
    bld="$base/build/openfhe-linux"
    inst="$base/build/openfhe-install-linux"
    "$cmake" -S "$src" -B "$bld" \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX="$inst" \
      -DCMAKE_C_COMPILER="${CC:-gcc}" \
      -DCMAKE_CXX_COMPILER="${CXX:-g++}" \
      -DNATIVE_SIZE=64 \
      -DWITH_NATIVEOPT=ON \
      -DWITH_OPENMP=ON \
      -DBUILD_UNITTESTS=OFF \
      -DBUILD_EXAMPLES=OFF \
      -DBUILD_BENCHMARKS=OFF
    ;;
  *) echo "unsupported platform" >&2; exit 2 ;;
esac
"$cmake" --build "$bld" --parallel "${BUILD_JOBS:-2}"
"$cmake" --install "$bld"
if test "$(uname -s)" = Darwin; then
  for lib in "$inst/lib/"*.dylib; do
    install_name_tool -change /opt/homebrew/opt/libomp/lib/libomp.dylib "$omp/lib/libomp.dylib" "$lib"
    codesign --sign - --force "$lib"
  done
fi
