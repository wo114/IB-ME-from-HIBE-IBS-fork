#!/usr/bin/env bash
# Run the local demo with the prescribed Sage environment and explicit engines.
set -euo pipefail
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
sage_python="$HOME/miniconda3/envs/sage/bin/python"
native_root="${IBME_DEMO_NATIVE_ROOT:-$HOME/.cache/ibme-native-tools/demo-runtime-v1}"
if [[ ! -x "$sage_python" ]]; then
  echo '需要 WSL 的 ~/miniconda3/envs/sage/bin/python。' >&2
  exit 2
fi
cd "$project_root"
export PYTHONPATH="$project_root/src${PYTHONPATH:+:$PYTHONPATH}"
export OMP_NUM_THREADS="${OMP_NUM_THREADS:-4}"
export OPENBLAS_NUM_THREADS="${OPENBLAS_NUM_THREADS:-1}"
if [[ "${1:-}" == '--build-native' ]]; then
  shift
  "$sage_python" -m ibme.hibe.latte.native.build --prefix "$native_root/latte"
  "$sage_python" -m ibme.ibs.certified.native.build --prefix "$native_root/mldsa"
  "$sage_python" -m ibme.ibs.certified.falcon_native.build --prefix "$native_root/falcon"
fi
export IBME_LATTE3_EXECUTABLE="${IBME_LATTE3_EXECUTABLE:-$native_root/latte/bin/ibme-latte3}"
export IBME_CERTIFIED_SIGNATURE_BIN_DIR="${IBME_CERTIFIED_SIGNATURE_BIN_DIR:-$native_root/mldsa/bin}"
export IBME_CERTIFIED_FALCON_BIN_DIR="${IBME_CERTIFIED_FALCON_BIN_DIR:-$native_root/falcon/bin}"
if [[ "${1:-}" == '--wheel' ]]; then
  shift
  if [[ $# -eq 0 ]]; then
    echo '--wheel 需要本地 IB-ME wheel 文件路径。' >&2
    exit 2
  fi
  runtime_wheel="$1"
  shift
  exec "$sage_python" "$project_root/experiments/research/wsl_wheel_runtime.py" --wheel "$runtime_wheel" -- "$@"
fi
exec "$sage_python" -m ibme.webui "$@"
