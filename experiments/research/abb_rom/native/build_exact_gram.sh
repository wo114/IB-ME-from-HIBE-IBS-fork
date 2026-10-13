#!/bin/sh
set -eu
# Run in WSL; override only the task-specific install prefix if desired.
sage_prefix="$HOME/miniconda3/envs/sage"
tool_prefix="${IBME_NATIVE_PREFIX:-$HOME/.cache/ibme-native-tools/exact-gram-v1}"
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
mkdir -p "$tool_prefix/bin"
g++ -O3 -std=c++17 -I"$sage_prefix/include" "$source_dir/exact_gram.cpp" \
    -L"$sage_prefix/lib" -Wl,-rpath,"$sage_prefix/lib" -lflint -lgmp \
    -o "$tool_prefix/bin/ibme-exact-gram"
"$tool_prefix/bin/ibme-exact-gram" --version
