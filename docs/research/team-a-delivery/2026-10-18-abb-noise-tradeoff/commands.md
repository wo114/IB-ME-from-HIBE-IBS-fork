# 复现命令

固定 lattice-estimator 必须位于仓库外、HEAD 为 `53da5982597709ba0fdf94ea37a84d822310fd84` 且工作树干净。下面用 `<estimator-dir>` 表示该目录。输出文件必须不存在；探针会先独占创建，避免覆盖旧证据。

## 本机实际命令（Nix Sage 10.9）

```sh
export PYTHONPATH="$PWD/src:$PWD:<estimator-dir>"
nix-shell -p sage --run "sage -python -u -m experiments.research.abb_rom.noise_tradeoff_probe \
  --estimator-path <estimator-dir> \
  --output test-results/abb-noise-tradeoff/parameter-card.json \
  --runtime-output test-results/abb-noise-tradeoff/runtime-summary.json"

nix-shell -p sage --run 'PYTHONPATH=src:. sage -python -m pytest -q \
  tests/test_abb_noise_tradeoff.py tests/test_matrix_hibe_scaled_screen.py'
```

## WSL 移交命令

```sh
export PYTHONPATH="$PWD/src:$PWD:<estimator-dir>"
~/miniconda3/envs/sage/bin/python -u -m experiments.research.abb_rom.noise_tradeoff_probe \
  --estimator-path <estimator-dir> \
  --output test-results/abb-noise-tradeoff/parameter-card.json \
  --runtime-output test-results/abb-noise-tradeoff/runtime-summary.json

~/miniconda3/envs/sage/bin/python -m pytest -q \
  tests/test_abb_noise_tradeoff.py tests/test_matrix_hibe_scaled_screen.py
```

以上命令分别运行 AP09 根侧 Euclidean SIS 条件比较和密文侧 LWE 比较，不生成密钥，不读取生产随机数，也不运行高维 BasisDel。根侧两个调用都明确没有有限返回时，JSON保留 `no_finite_estimate` 和原始字段，不换算成安全成本；若密文侧达到128，只可进入不授予安全或运行准入的实现研究层。若要重复运行，使用新的输出目录；不要删除或覆盖已有结果来隐藏失败。
