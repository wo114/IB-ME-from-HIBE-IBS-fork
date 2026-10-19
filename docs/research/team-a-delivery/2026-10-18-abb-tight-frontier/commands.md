# 复现命令

本批机器没有使用仓库或其它电脑写死的 Sage 路径。实际环境为 Nix Sage 10.9；移交到 WSL 时应替换为该成员自己的 `~/miniconda3/envs/sage`，不要提交某台电脑的绝对环境路径。

固定 estimator checkout：

```bash
git -C /tmp/ibme-lattice-estimator rev-parse HEAD
# 53da5982597709ba0fdf94ea37a84d822310fd84
git -C /tmp/ibme-lattice-estimator status --short
```

正式参数卡运行（输出路径必须尚不存在，避免覆盖旧证据）：

```bash
NIX_CONFIG='flake-registry = ' nix-shell -p sage --run \
  "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:.:/tmp/ibme-lattice-estimator \
   sage -python -u -m experiments.research.abb_rom.tight_parameter_frontier \
   --baseline-card docs/research/team-a-delivery/2026-10-18-abb-noise-tradeoff/parameter-card.json \
   --estimator-path /tmp/ibme-lattice-estimator \
   --output docs/research/team-a-delivery/2026-10-18-abb-tight-frontier/parameter-card.json \
   --runtime-output docs/research/team-a-delivery/2026-10-18-abb-tight-frontier/runtime-summary.json"
```

定向测试：

```bash
NIX_CONFIG='flake-registry = ' nix-shell -p sage --run \
  "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. sage -python -m pytest -q \
   tests/test_abb_tight_parameter_frontier.py"
```

ABB 回归：

```bash
NIX_CONFIG='flake-registry = ' nix-shell -p sage --run \
  "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. sage -python -m pytest -q \
   tests/test_abb_*.py tests/test_matrix_hibe_scaled_screen.py"
```

交付检查：

```bash
git diff --check
git status --short
```
