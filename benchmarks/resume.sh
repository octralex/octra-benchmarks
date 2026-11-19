#!/usr/bin/env bash
set -euo pipefail
base="$(cd "$(dirname "$0")" && pwd)"
cd "$base"
mkdir -p state
export PYTHONHASHSEED=0 TZ=UTC LC_ALL=C
mark() {
  python3 progress.py "$1" "$2"
}
stage() {
  local name="$1"
  shift
  mark "$name" STARTED
  if "$@" > "state/${name}.log" 2>&1; then
    mark "$name" FINISHED
  else
    mark "$name" FAILED
    return 1
  fi
}
supervise() {
  case "$(uname -s)" in
    Darwin) caffeinate -i "$@" ;;
    Linux) systemd-inhibit --what=sleep --why="PVAC benchmark measurement" "$@" ;;
    *) return 2 ;;
  esac
}
correctness() {
  if test "$(uname -s)" = Darwin; then
    caffeinate -i "$@"
  else
    "$@"
  fi
}
stage 00-manifest python3 manifest.py
stage 01-controls correctness python3 controls.py
stage 02-full-smoke correctness python3 harness.py smoke
stage 03-tfhe16-d64 correctness python3 resume_d64.py
stage 03c-representation-selection supervise python3 representations.py
stage 04-same-key-sessions correctness python3 schedule.py session-smoke
stage 05-diagnostics correctness python3 diagnostics.py
stage 06-parameters python3 parameter_manifest.py
stage 06a-bigint-sanitizer correctness bash build-sanitizer.sh
stage 06b-wide-controls correctness python3 wide_controls.py
stage 06b2-wide-batches correctness python3 wide_batch_controls.py
stage 06b3-representation-controls python3 representation_controls.py
stage 06b4-two-pass-controls python3 two_pass_controls.py
stage 07-pilot supervise python3 schedule.py pilot
stage 08-micro supervise python3 schedule.py micro
stage 09-session-pilot supervise python3 schedule.py session-pilot
stage 10-freeze python3 schedule.py freeze
stage 11-manifest python3 manifest.py
if test "${RUN_MAIN:-0}" = 1; then
  stage 12-forward supervise python3 schedule.py run --pass forward
  stage 13-reverse supervise python3 schedule.py run --pass reverse
  stage 14-tables python3 tables.py
  stage 15-export python3 export_samples.py
  stage 16-verify python3 verify_tables.py
  mark MAIN_COMPLETE FINISHED
else
  mark READY FINISHED
fi
