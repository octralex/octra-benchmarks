#!/usr/bin/env bash
set -euo pipefail
base="$(cd "$(dirname "$0")" && pwd)"
cd "$base"
mkdir -p sources third-party
fetch() {
  local url="$1" output="$2" expected="$3"
  if test ! -f "$output"; then
    curl -fL --retry 3 "$url" -o "$output"
  fi
  local actual
  if command -v sha256sum >/dev/null; then
    actual="$(sha256sum "$output" | awk '{print $1}')"
  else
    actual="$(shasum -a 256 "$output" | awk '{print $1}')"
  fi
  if test "$actual" != "$expected"; then
    echo "source hash mismatch: $output" >&2
    return 1
  fi
}
fetch https://github.com/openfheorg/openfhe-development/archive/b59e1f291965f14fbee5172cd83a20f5b856204f.tar.gz openfhe.tar.gz 2bc4ccd84c7a64a64c72fd3ed36b585406365f363b1672db0cef1e9a588f879b
fetch https://github.com/zama-ai/tfhe-rs/archive/e8f3926bb53d7eea95e8a7f581f60aae1c7aba16.tar.gz tfhe-rs.tar.gz 31aa5813378a3563b578d869376d247631f46a2f17137d9cb8a14953eb285e03
if test ! -d pvac-git/.git; then
  git clone --filter=blob:none --no-checkout https://github.com/octra-labs/pvac_hfhe_cpp.git pvac-git
fi
git -C pvac-git checkout 071b0e909c119de815e284b347c4bd979cb59ef3
git -C pvac-git diff --quiet HEAD
git -C pvac-git archive --format=tar --output="$base/sources/pvac-include.tar" 071b0e909c119de815e284b347c4bd979cb59ef3 include
if test ! -d sources/pvac-include/pvac; then
  mkdir -p sources/pvac-include
  tar -xf sources/pvac-include.tar -C sources/pvac-include --strip-components=1
fi
if test ! -d openfhe-development-b59e1f291965f14fbee5172cd83a20f5b856204f; then
  tar -xzf openfhe.tar.gz
fi
if test ! -d tfhe-rs-e8f3926bb53d7eea95e8a7f581f60aae1c7aba16; then
  tar -xzf tfhe-rs.tar.gz
fi
if test ! -d openfhe-git/.git; then
  git clone --filter=blob:none --no-checkout https://github.com/openfheorg/openfhe-development.git openfhe-git
fi
git -C openfhe-git checkout b59e1f291965f14fbee5172cd83a20f5b856204f
for attempt in 1 2 3; do
  if git -C openfhe-git submodule update --init --depth 1 --force; then
    break
  fi
  if test "$attempt" = 3; then
    echo "openfhe submodule fetch failed" >&2
    exit 1
  fi
done
git -C openfhe-git diff --quiet HEAD
if test "$(uname -s)" = Darwin; then
  python3 fetch-libomp.py
fi
