#!/usr/bin/env bash
# Generate a fresh C2 target CLI state and ciphertext for the wrong-identity
# and BYTEAUTH receipts.  Private state stays in a new temporary directory and
# is never written into the repository.
#
# Usage:
#   target_state_setup.sh [state-dir] [ciphertext-path]
#
# If state-dir is omitted, a new mktemp directory is used.  An explicitly
# supplied state-dir or ciphertext path must not already exist.
set -euo pipefail
REPO=$(cd "$(dirname "$0")/../../../.." && pwd)
cd "$REPO"
export PYTHONPATH=src:.
PY=${PYTHON:-$HOME/miniconda3/envs/sage/bin/python}
WORKROOT=${TMPDIR:-/tmp}

if [ "$#" -gt 2 ]; then
  echo "usage: target_state_setup.sh [state-dir] [ciphertext-path]" >&2
  exit 2
fi
if [ -n "${1:-}" ]; then
  STATE=$1
  [ ! -e "$STATE" ] || { echo "state path already exists: $STATE" >&2; exit 2; }
else
  STATE=$(mktemp -d "$WORKROOT/lai-target-state.XXXXXXXX")
fi
CT=${2:-"$STATE/ct.bin"}
[ ! -e "$CT" ] || { echo "ciphertext path already exists: $CT" >&2; exit 2; }
mkdir -p -- "$(dirname "$CT")"
mkdir -p -- "$STATE"
MSG="$STATE/message.bin"
printf 'target-cli-msg' > "$MSG"

start=$(date +%s)
step() {
  local name=$1; shift
  local s e rc
  s=$(date +%s)
  rc=0
  "$@" > "$STATE/$name.log" 2>&1 || rc=$?
  e=$(date +%s)
  echo "$name rc=$rc sec=$((e-s))" | tee -a "$STATE/timings.txt"
  tail -2 "$STATE/$name.log"
  return "$rc"
}

step setup "$PY" -m ibme.cli setup --hibe lai-ideal-hibe --ibs luo-module \
  --hibe-params target-research --ibs-params research --transport hybrid \
  --state "$STATE"
step receiver_alice "$PY" -m ibme.cli issue-receiver-key alice --state "$STATE"
step receiver_carol "$PY" -m ibme.cli issue-receiver-key carol --state "$STATE"
step sender_bob "$PY" -m ibme.cli issue-sender-key bob --state "$STATE"
step encrypt "$PY" -m ibme.cli encrypt --sender bob --receiver alice \
  --in "$MSG" --out "$CT" --state "$STATE"

echo "STATE=$STATE"
echo "CT=$CT"
echo "MESSAGE=$MSG"
echo "STATE_BYTES=$(du -sb "$STATE" | cut -f1)"
echo "CT_BYTES=$(stat -c %s "$CT")"
echo "TOTAL_SEC=$(( $(date +%s) - start ))"
