#!/usr/bin/env bash
set -euo pipefail
node=${1:?path to a lite_node clone}
rev=8f785a93a4e7392a0f3e65674f9de89854d33dbc
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git -C "$node" archive "$rev" pvac pvac_ffi | tar -x -C "$work"
cp "$(dirname "$0")/node_pvac_key_probe.cpp" "$work/"
cd "$work"
g++ -std=c++17 -O3 -march=native -I pvac/include -I pvac node_pvac_key_probe.cpp pvac/pvac_c_api.cpp -o probe -lpthread
echo "lite_node $rev"
g++ --version | head -1
./probe
