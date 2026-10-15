# SRGG 数值稳定性与 HNF 聚合审计

本批在 `fa7bb95` 的 SRGG 持久发钥交付之上，补充三个尚未闭合的研究核验入口：

1. `numeric_audit.py` 用同一条确定性测试字节流，分别在 128 bit 和 192 bit 实数精度下运行公开的 SampleF 2 维夹具与 SampleP 4 维、2 阶段 Schur 夹具，记录输出分歧和中止情况。
2. 同一工具对 `degree=2, rank=1, p=5, b=3, digits=1, Q=15` 的小型公开扰动夹具执行 HNF 恢复，只导出成功次数、首块变化次数和恢复向量平方范数的聚合范围。
3. 同一工具按 Algorithm 3 的 `sample_geometry` 对非零相关 6 维夹具统计完整均值和协方差，目标采用 `Σ_p/(2π)`。

这些结果是有限样本和确定性字节流下的数值诊断。它们不证明连续 SampleF 的总变差、不证明 HNF 后用户密钥分布，也不构成强不可伪造、安全等级或 HIBE 组合准入。

## 收据

指定 WSL Sage 环境的运行命令：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m \
  experiments.research.candidates.srgg.numeric_audit \
  --precision-samples 64 --hnf-repetitions 32 --covariance-samples 4096 \
  --output build/outputs/srgg-numeric-audit-2026-10-15/numeric.json
```

运行环境为 Sage 10.9、Python 3.13.15、WSL2。收据见 [numeric.json](numeric.json)：
源码、收据和结果摘要的 SHA-256/字节数见 [MANIFEST.json](MANIFEST.json)。

- SampleF：64/64 对成功，0/64 输出分歧，0 次中止；
- SampleP：64/64 对成功，0/64 输出分歧，0 次中止；
- `sample_geometry`：4096 个完整 6 维样本，目标协方差按 `Σ_p/(2π)`，最大绝对协方差误差约 `1.525`，最大对角相对误差约 `0.0144`，非零交叉项最大绝对误差约 `0.699`；
- HNF：32/32 次恢复完成，0 次中止，31 次首块发生修正，平方范数范围为 45–615，均值为 `2003/8`。

“0 次分歧”和矩阵误差只描述该组夹具、精度档和固定样本，工具报告仍保留 `continuous_stage_tv_certified=false` 的边界。HNF 聚合使用的是研究探针配置，不能外推到默认 `n=8,d=1,p=257,b=31,w=3,Q=7656287` 档。

本批继续使用 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。默认 SRGG 参数、持久服务、公开 8 bit 挑战伪造反例及现有安全限制均不变。
