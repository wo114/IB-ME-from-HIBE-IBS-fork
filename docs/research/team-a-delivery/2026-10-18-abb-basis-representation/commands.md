# 复现命令

本机没有使用仓库内或其它用户写死的 Sage 路径；以下命令使用 Nix 提供的 SageMath 10.9。在仓库根目录执行：

```sh
nix-shell -p sage --run 'PYTHONPATH=src:. sage -python -m pytest -q tests/test_abb_basis_representation.py'
```

重新生成报告时应选择不存在的新输出路径；探针用排他创建保留失败现场，不覆盖已有证据：

```sh
nix-shell -p sage --run 'PYTHONPATH=src:. sage -python -m experiments.research.abb_rom.basis_representation_probe \
  --source-card docs/research/team-a-delivery/2026-10-18-abb-noise-tradeoff/parameter-card.json \
  --output /tmp/abb-basis-representation-card.json \
  --runtime-output /tmp/abb-basis-representation-runtime.json'
```

相关 ABB 回归：

```sh
nix-shell -p sage --run 'PYTHONPATH=src:. sage -python -m pytest -q \
  tests/test_abb_basis_representation.py \
  tests/test_abb_noise_tradeoff.py \
  tests/test_matrix_hibe_scaled_screen.py'

nix-shell -p sage --run 'PYTHONPATH=src:. sage -python -m pytest -q \
  tests/test_abb_*.py tests/test_matrix_hibe_scaled_screen.py'
```

完整性检查：

```sh
nix-shell -p sage --run 'sage -python -m json.tool \
  docs/research/team-a-delivery/2026-10-18-abb-basis-representation/parameter-card.json >/dev/null'
nix-shell -p sage --run 'sage -python -m json.tool \
  docs/research/team-a-delivery/2026-10-18-abb-basis-representation/runtime-summary.json >/dev/null'
git diff --check
```
