复审固定 head `a81773564253660d4ef16ebebee350d2d057f394`。此前对 `20d75e9` 的两项 P1 阻塞已在该版本解决，可以按独立研究后端范围合并。

1. 根、委派与签名实际走全维扰动 `p`、残差 `u-Ap`、完整三进制陪集 Gaussian 及 `p+Jx`；原始整数陷门的精确 PSD 准入发生在取熵前。矩阵抽 nk 个完整列，环版抽 k 个完整系数向量后构造 negacyclic 旋转；恢复检查根/用户关系及环展开。旧的精确低秩关系有专门回归，未继续将其当 Gaussian 输出。
2. Setup、H1/H2 使用有限预算拒绝取模；SHAKE 流游标推进、重算前缀和字节/试次失败处理已有独立检查。v2 magic、域分隔与具体路线对象拒绝旧 v1 和跨 SIS/RSIS 混用，不自动迁移或重发旧状态。
3. 复核固定发钥的 pending/failed、同身份复用、独立进程与锁、保存故障、参数/公钥 pin、损坏状态保留及有界解析。私有连续采样计划仅在对象内缓存。
4. 本轮在规定 WSL Sage 环境执行 `PYTHONPATH=src:. PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 OMP_NUM_THREADS=4 OPENBLAS_NUM_THREADS=1 ~/miniconda3/envs/sage/bin/python -m pytest -q -p no:cacheprovider tests/test_sageloli_ibs.py tests/test_sageloli_sampling.py tests/test_sageloli_uniform.py tests/test_sageloli_service_recovery.py tests/test_sageloli_probe.py --junitxml=test-results/pr-review-2026-10-17/pr34.xml`：145 passed，0 failed，0 skipped，174.86 s。远端 23 项成功、1 项预期手动安全检查未执行；与已合入 PR36 的 main 合并树无冲突。

范围仍为 SIS n2/k4/m16/q81 和 RSIS d4/k9/l22/q19683 的真实教学研究后端。总连续/有限采样 TV、固定服务的 ROM/QROM 对应、正式参数与 HIBE/registry/CLI 组合均未因此获准；保留 `none/false/false`。本次未对外部系统进行安全测试，测试产物不发布私钥、随机带或签名样本。
