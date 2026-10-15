# SRGG 固定发钥、并发和异常恢复交付

本批在现有 SRGG 完整研究 IBS 之上补齐独立持久 `FixedIssuer`。目标是固定发钥和本地状态可靠性：同身份重启后复用同一把密钥；合作进程并发请求由本地锁串行化；发钥、保存、删除标记或进程中途失败时保留阻断状态，禁止悄悄重抽。原始 `Backend`、签名方程、采样器和公共 registry/CLI 未改。

实现入口：[srgg_service.py](../../../../src/ibme/ibs/srgg_service.py)，契约见 [srgg-issuer.md](../../../specs/srgg-issuer.md)。由于 SRGG 原始后端会拒绝已标记 pending 的身份，服务在落盘 pending 后使用只含已发身份的工作 `MasterSecret` 执行一次原始提取，再把成功 key 绑定回持久快照。

## 验收证据

指定 WSL Sage 环境运行：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_service.py
```

结果为 **11 passed / 0 failed / 0 skipped**，覆盖：

- 同身份重启、零熵缓存读取和恢复后签验；
- 两个进程同时请求同一身份，输出同一 key 摘要；
- 原始提取失败、返回错误 key、最终保存失败和硬退出后的 pending 阻断；
- 损坏快照、容量、身份和已有空目录边界。

同一 worktree 的既有 SRGG 回归为 **132 passed / 0 failed**：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q \
  tests/test_srgg_ibs_backend.py tests/test_srgg_full_sampling.py \
  tests/test_srgg_sampling.py tests/test_srgg_algebra.py tests/test_srgg_geometry.py
```

固定服务公开生命周期收据由以下命令生成，输出不含私钥、盐、种子或签名：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m \
  experiments.research.candidates.srgg.service_audit \
  --output build/outputs/srgg-service-2026-10-15/service.json
```

本批源码和文档指纹、测试计数与安全标识见同目录 [MANIFEST.json](MANIFEST.json)；清单不包含自身。

采样和代数数值核验沿用独立脚本，输出在 `build/outputs/srgg-service-2026-10-15/numeric/`：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m \
  experiments.research.candidates.srgg.audit \
  --output build/outputs/srgg-service-2026-10-15/numeric/algebra-geometry.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m \
  experiments.research.candidates.srgg.sampling_audit \
  --output build/outputs/srgg-service-2026-10-15/numeric/sampling.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m \
  experiments.research.candidates.srgg.perturbation_audit --repetitions 64 \
  > build/outputs/srgg-service-2026-10-15/numeric/perturbation.json
```

本轮数值结果包括 36 个二进制挑战、9 个协方差形状检查、36,864 个标量统计样本、27 个有限联合分布检查和 64/64 次原始/HNF 方程通过。Table 3 的 `b*r` 宽度配方与有限 SampleZ 映射通过；字面 Algorithm 6 宽度与该配方的有限分布距离约为 0.455–0.498，不能混写成同一采样器。连续阶段总 TV、HNF 后密钥分布、ζ 与 Table 3 的最终参数对应仍未闭合，现有收据继续标记这些限制。

## 参数和安全边界

SRGG 研究档仍为 `n=8, d=1, p=257, b=31, w=3, Q=7656287`，身份上限 256 B，消息上限 4096 B，服务默认最多 16 个身份。该档挑战仅 8 bit，公开固定点伪造仍可构造；`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false` 不变。服务可靠性测试不能替代正式安全证明、参数估计或 Wang 组合前提核验。
