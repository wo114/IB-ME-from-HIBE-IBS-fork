#!/usr/bin/env bash
# Task-scoped Linux prerequisites. No experiments, disks or SSH configuration.
set -euo pipefail
task_dir=${1:?Usage: prepare_environment.sh TASK_DIRECTORY}
mkdir -p "$task_dir/environment"
exec > >(tee -a "$task_dir/environment/prepare-all.log") 2>&1
date -u +%FT%TZ
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq build-essential pkg-config ca-certificates curl \
    python3-venv libssl-dev libmpfr-dev libgmp-dev libmpc-dev \
    libopenblas-dev libquadmath0 time
python3 -m venv "$task_dir/venv"
"$task_dir/venv/bin/python" -m pip install --only-binary=:all: \
    'setuptools>=68' wheel numpy scipy pytest psutil gmpy2 'cryptography>=49,<51'
"$task_dir/venv/bin/python" -m pip freeze > "$task_dir/environment/requirements.lock.txt"
if [ ! -x "$HOME/miniconda3/bin/conda" ]; then
    installer=Miniforge3-Linux-x86_64.sh
    cd "$task_dir/environment"
    # Frozen from the publisher's release API on 2026-10-19; a mirror is
    # accepted only if its bytes match the publisher's pinned SHA-256.
    expected=281b0ac7d550802efc81af633225a5e6116d29ae72f3ab4eae7168c3931a4c05
    if ! curl -fL --retry 1 --speed-limit 1048576 --speed-time 15 -o "$installer" \
        "https://github.com/conda-forge/miniforge/releases/download/26.7.2-0/$installer"; then
        curl -fL --retry 1 --max-time 180 -o "$installer" \
            "https://mirrors.tuna.tsinghua.edu.cn/github-release/conda-forge/miniforge/LatestRelease/$installer"
    fi
    printf '%s  %s\n' "$expected" "$installer" | sha256sum -c -
    bash "$installer" -b -p "$HOME/miniconda3"
fi
"$HOME/miniconda3/bin/conda" create -y -p "$HOME/miniconda3/envs/sage" \
    --override-channels -c conda-forge --strict-channel-priority \
    python=3.12 sage numpy scipy pytest psutil gmpy2 'cryptography>=49,<51'
"$HOME/miniconda3/bin/conda" list -p "$HOME/miniconda3/envs/sage" --explicit \
    > "$task_dir/environment/sage-explicit.lock.txt"
"$HOME/miniconda3/envs/sage/bin/python" -c \
    'import sage.all,numpy,scipy,pytest,psutil,gmpy2,cryptography; print("all task imports passed")'
pkg-config --modversion openssl mpfr gmp openblas
g++ --version | head -1
df -h "$task_dir"
date -u +%FT%TZ
