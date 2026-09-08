#!/usr/bin/env sh
# Run clippy over every target and every feature, and leave machine-readable
# evidence behind.
#
# This exists because nothing runs clippy for this repository: the GitHub
# Actions workflows are disabled across all eleven repositories, so the lint
# baseline went red and stayed red. A red baseline is not just noise — it means
# "clippy is clean" can never be used as an acceptance judgement.
#
# Both halves of the command matter:
#
#   * `--all-features` — `cedar` gates policy modules
#     out of the default build, so without it those files are never
#     type-checked at all.
#   * `-D warnings` — a warning nobody fails on is a warning nobody fixes.
#
# Reading the tail is not enough on a failing run: clippy stops compiling a
# crate at its first failure and prints `build failed, waiting for other jobs
# to finish`, so the findings you see are a floor, not the total. Fix them and
# run again until this exits 0.
#
# Output contract: the verdict goes to files, not to the terminal tail. Read
# `$COAUTH_CLIPPY_GATE_DIR/summary.txt`.
#
# Usage:
#   scripts/clippy_gate.sh                    # whole workspace, all features
#   scripts/clippy_gate.sh -p coauth-backend  # narrow re-run, same contract

set -eu

gate_dir="${COAUTH_CLIPPY_GATE_DIR:-target/clippy-gate}"
target_dir="${COAUTH_CLIPPY_GATE_TARGET_DIR:-target/clippy}"

mkdir -p "$gate_dir"
log="$gate_dir/clippy.log"
summary="$gate_dir/summary.txt"
status="$gate_dir/status.txt"

echo "clippy gate: target=$target_dir log=$log"

set +e
CARGO_TARGET_DIR="$target_dir" cargo clippy --locked \
    --workspace --all-targets --all-features "$@" -- -D warnings > "$log" 2>&1
code=$?
set -e

echo "$code" > "$status"

# Keep the lines a reviewer acts on: every diagnostic header and the source
# location that follows it.
grep -E '^(error(\[E[0-9]+\])?:|warning:|\s+--> )' "$log" > "$summary" || true

echo "--- $summary ---"
cat "$summary"
echo "--- exit $code (full log: $log) ---"
exit "$code"
