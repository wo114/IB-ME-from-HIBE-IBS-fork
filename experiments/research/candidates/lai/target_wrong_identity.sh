#!/usr/bin/env bash
# C2 target wrong-identity matrix (wrong receiver / wrong sender / both).
# Requires target CLI state and ciphertext from the lifecycle documented in
# docs/research/team-c-delivery/2026-10-18-lai-target-parameters/README.md.
# Usage: target_wrong_identity.sh [state] [ciphertext]
set -euo pipefail
REPO=$(cd "$(dirname "$0")/../../../.." && pwd)
cd "$REPO"
export PYTHONPATH=src:.
PY=${PYTHON:-$HOME/miniconda3/envs/sage/bin/python}
STATE=${1:-/tmp/lai-target-cli}
CT=${2:-/tmp/lai-target-ct.bin}
if [ ! -d "$STATE" ] || [ ! -f "$CT" ]; then
  echo "target state directory and ciphertext file are required" >&2
  exit 2
fi
# Never remove an existing path: retain each run for inspection.  An explicit
# WORK must be a new directory, otherwise mkdir fails before any writes.
if [ -n "${WORK:-}" ]; then
  mkdir -- "$WORK"
else
  WORK=$(mktemp -d "${TMPDIR:-/tmp}/lai-wrong-identity.XXXXXXXX")
fi
echo "work directory: $WORK"
cp -a "$STATE" "$WORK/recv"
cp -a "$STATE" "$WORK/send"
cp -a "$STATE" "$WORK/both"

run_case() {
  local name=$1 receiver=$2 sender=$3
  local start end rc
  start=$(date +%s)
  rc=0
  "$PY" -m ibme.cli decrypt --receiver "$receiver" --sender "$sender" \
    --in "$CT" --out "$WORK/$name.out" --state "$WORK/$name" \
    > "$WORK/$name.log" 2>&1 || rc=$?
  end=$(date +%s)
  echo "$name rc=$rc sec=$((end-start))"
  tail -2 "$WORK/$name.log"
  echo "$rc" > "$WORK/$name.rc"
}

run_case recv carol bob &
P1=$!
run_case send alice mallory &
P2=$!
run_case both carol mallory &
P3=$!
wait "$P1" "$P2" "$P3"

fail=0
for name in recv send both; do
  [ "$(cat "$WORK/$name.rc" 2>/dev/null)" = "1" ] || fail=1
  grep -q '^BOTTOM$' "$WORK/$name.log" || fail=1
done
[ "$fail" = "0" ] && echo WRONG_IDENTITY_MATRIX_OK || echo WRONG_IDENTITY_MATRIX_FAILED
exit "$fail"
