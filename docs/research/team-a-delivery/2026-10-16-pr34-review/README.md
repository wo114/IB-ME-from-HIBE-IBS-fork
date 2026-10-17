# PR34 固定源码复核：要求修改，暂不合并

2026-10-16；审查目标为 [PR34](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/34) 的 `20d75e9b9dcf2ceb8509cedd867a5c479e03af62`。远端仍 open/未合并，23 项检查成功，1 项手动 `strict-security` 跳过，未把跳过计为成功。没有修改 B 的原语、公共注册器或协议。审查只读取远端元数据，在本地使用临时教学测试钥；没有远端安全测试、实际用户数据、密钥材料输出或伪造签名。

## 需要修改的两项

1. **P1：用户钥委派缺少全维扰动，暴露根陷门的精确线性关系。** `algebra.py:120–133` 的矩阵输出上下两块满足 `T_top=R*T_bottom`；`:216–226` 环版展开后也相同。这是整数上的等式，不只是模 q 方程。在当前两个默认配置各 3 次本地测试中，序列化往返后的单个用户钥底块均满秩，因此用户钥唯一确定根陷门。测试只核对零残差与秩，没有执行恢复或输出任何私值。范围是本次 6 个样本和源码给出的精确关系，不声称所有随机输出底块必定可逆。必须恢复论文 SampleD/SampleDR 所需的完整扰动与条件检查，并同时核对签名采样；规范 codec、调高 q、范数拒绝、`none/false` 标记都不能修复这个关系。既有 `probe.py` 的 `sample_preimage` 包含完整扰动，新增后端没有使用该路径。
2. **P1：Setup 与 H1/H2 的模约减有显著偏差。** `backend.py:80–82` 以及 `hashing.py:28–51` 都用固定字节整数 `% q`。q=81 的单系数 TV 距均匀为 `221/5184`（约 4.263%）；q=19683 为 `21400613/322486272`（约 6.636%）。这些是精确概率，不是抽样统计。应为随机源和 XOF 分别实现有资源帽的拒绝取模，保留域分隔与中止语义，不能把当前输出对应为论文的均匀矩阵/随机预言机。

## 本轮验证

指定 WSL `~/miniconda3/envs/sage`，Sage 10.9 / Python 3.13.14；完整软件信息及固定源文件 SHA256 见[本地诊断](evidence/local-sampler-checks.json)。参数为矩阵 `(n,k,m,q)=(2,4,16,81)`、环 `(d,k,l,q)=(4,9,22,19683)`；身份 `test-user` 为 9 B，诊断不调用 Sign，消息长度不适用。各路线 3 次，固定测试随机流，与实际安全熵分开。

在 PR34 固定源码目录执行已有测试：

```sh
PYTHONPATH=src:. PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  ~/miniconda3/envs/sage/bin/python -m pytest \
  tests/test_sageloli_ibs.py tests/test_sageloli_probe.py -q \
  --junitxml=test-results/pr34-review-existing.xml
```

结果为 **34 passed / 0 skipped**，19.25 秒；[JUnit](evidence/existing-tests.xml)。原测试成功没有覆盖上述缺陷，不能作为合并的充分依据。

在含本批诊断脚本的仓库根运行以下命令；`<固定PR34源码目录>`必须是上述提交且相关文件无修改，输出必须不存在：

```sh
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python \
  experiments/research/pr34_sampling_review.py \
  --source-root <固定PR34源码目录> --output test-results/pr34-local-review.json
```

6 项本地代数诊断全部确认零残差和底块满秩。脚本仅保存参数、秩、布尔值、公开概率与环境；不保存测试钥、随机带、签名或用户数据。首次封装命令因 Linux git 不能直接解析 Windows worktree 的 gitdir 而在读源码阶段退出，未采样；随后增加显式路径转换并完成复放，未修改原语判据。

两条路线均为教学参数，ROM/固定服务/有限分布和正式参数对应仍未准入，保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。本批没有新增安全实例；测试与线性关系诊断不替代安全证明。下一步由 B 修复后在新 head 重新核对，当前不合并；A 的工作不依赖 PR34。
