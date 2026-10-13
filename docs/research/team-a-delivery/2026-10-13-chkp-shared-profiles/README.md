# A3：CHKP 配置复用公共矩阵引擎

2026-10-13。先完成[固定 PR 审查](../2026-10-13-pr-review/README.md)，再推进 A3。当前分支新增的是公共工具适配及交接提案；队友 `src/ibme/lattice/chkp/`、registry、protocol、CLI 没有在当前分支修改或合入。

## 已完成实物

`src/ibme/lattice/matrix_sampling/chkp_profiles.py` 在现有 scalar / GPV / RandBasis / ToBasis 引擎上提供独立 CHKP 配置：scalar 平方宽度上限 2^88，显式 GPV 上限 512 维、输入 2048 bit，ToBasis 整数 8192 bit；原 first-suite 的 scalar 2^80 / GPV 256 维配置不自动扩大。字段相同的旧有限字节预算模板被重新校验、复制为目标配置，不修改原对象，也不接受任意宽 MatrixFiniteOptions。

GPV 保留精确父 GS 最大值供真实 ExtendedGPV 的全维 smoothing 检查，兼容原有有理权重诊断及整数分母视图；实际投影仍使用同一个 native QQ 引擎。异常域信息保留各配置原口径。Gaussian、中心更新、矩阵满格、独立性选择、范数中止、随机字节和 ToBasis 计算没有复制第二套实现。

新适配器默认仅接受共享 CHKP GPV。扩展 RandBasis 必须得到队友实际 ExtendedGPV，且其 parent 已使用共享引擎；未交接源码或旧平行引擎不会被隐式替代为伪采样器。额外 1 GiB 精确内容准入属于工程中止，不是进程 RSS 保证或新安全误差项；完整工作区失败概率仍未闭合。

## 独立固定对照与实际结果

[公开控制样例](../../../../tests/fixtures/chkp_shared_profile_controls.json) 由未改动的 PR14 head `87deec24f52c1c776a489566cf76f11d0d4a5aff` 生成并记录五份原源码 SHA256。样例使用事先声明的固定测试随机流、公开的 q=17 两维完整核格及一列扩展；没有真实系统 key、seed 或私密矩阵。每个用例同时比较结果和随机字节消费，不筛掉 ABORT。

- 3 个 scalar 配置（9、2^80、2^88，分别 16 次），3 个 GPV syndrome（各 8 次），3 个实际扩展 syndrome（各 8 次）。
- 普通 / 扩展 RandBasis 各 4 个预声明随机流；核对完整基、draws_used、独立向量数与熵消费。
- 规范基、ToBasis、窄/CHKP 输入域及精确 GS 条件另核。

当前 A 分支 core 批次 **60 passed / 7 skipped，9.84 s**；7 项是当前分支尚无队友 ExtendedGPV 的明确 skip。随后在独立候选副本中装入实际队友源码及提案桥接，相关 7 项全部实际执行，最终扩大批次 **1122 passed / 4 skipped，106.32 s**。4 项是外部旧私有/历史源码 witness 未提供；不计通过，不把重叠批次相加。

扩大批次覆盖全部 CHKP 专属测试、旧 first-suite 有限测试、matrix / ABB 原语测试与公共 research API。它不是重新生成 n=2 CHKP 的根/父/四叶，也不完成 ABB 正条件生命周期、全部 CLI/组合或正式安全准入。

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest \
  tests/test_chkp_matrix_profiles.py tests/test_matrix_finite_sampling.py tests/test_matrix_modular.py -q --tb=short
# 独立候选副本；先应用下述提案并放入本批 A 源码和控制样例。
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest \
  tests/test_chkp*.py tests/test_first_suite_finite_sampling.py tests/test_matrix_*.py \
  tests/test_abb_rom*.py tests/test_public_research_api.py -q --tb=short
```

中间失败原样保留：首个桥接漏导出导致 collection error；补导出后 40 项缺内部 gate 名称失败；随后扩大批次 7 项预算对象/诊断常量/异常信息兼容失败；定向修正阶段还保留 2 项异常文本失败。最后在同一候选源码重新跑扩大批次全部通过。没有改队友测试、用 skip 隐藏失败、调整 Gaussian 或删除旧收据。见 [validation-summary.json](validation-summary.json) 与原始 JUnit；最终 13 份候选源/测试文件 SHA256 同时固定。

环境沿用 WSL 指定 conda Sage 10.9 / Python 3.13.14，Core Ultra 9 275HX 开发机。本批时间仅是检查时间，不用于宣称完整 IB-ME 加速或公平排名。控制样例是教学代数与固定测试熵；生产默认随机源仍由公共引擎提供。

## 给统筹的具体接入提案

[coordinator-integration-proposal.patch](coordinator-integration-proposal.patch) 以 PR14 固定 head 为基点，包含 8 个路径：4 处冲突入口保留 A 当前窄适配，队友 4 个 runtime 文件变为公共引擎桥接；未改身份、协议、参数快照、固定地址或旧证据。原精确 rank helper 只保留兼容诊断，实际 RandBasis 由公共引擎执行。

该 patch 是接收者可审查的提案，**尚未应用到当前分支的队友文件**。应用前先接收本批新增 A 模块、GPV/scalar 兼容改动和测试样例；提案是零上下文 patch，用 `git apply --unidiff-zero --check` 在独立副本验证，实际应用也需 `--unidiff-zero`。候选副本的联合树来自 PR15 + PR14，只在忽略目录中解决冲突、放入桥接。当前分支没有制造待解决的 Git merge 状态。

统筹仍须负责实际共享入口合并、安装包/CLI/状态与完整组合复核，并为新组合记录新源码指纹；本批不能覆盖原 PR14 130 份历史源清单或改写其 44 项组合证据。源文件/测试变更与参考混合树逐项列在验证 JSON；新 backend 不由此登记或升级已准入数量。

## ABB pending 后续观察

已有 q104/m832 实例只有一次实际 Setup（6.180573 s、135174 私有随机字节）、父阶段 pending。进程已不在运行，最终中止原因、父总耗熵、RSS 和结束源码指纹未知；不存在通过收据。当前未提交参数筛查改动保留，没有恢复或提交它。

使用未改动 PR15 固定 archive，对该同一权威 master 做 `--restore-only`：实际 FAILED 地址恢复通过、私有熵调用 **0**，没有生成替代根、重发父或写原状态。见 [pr15-pending-restore.json](pr15-pending-restore.json)、[观察记录](abb-orphaned-pending-observation.json)。这确认墓碑，不确认父采样成功；原 running 文件仍保留为历史观察。

所有标记保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。SHAKE 工程实现、有限 Gaussian 与资源控制未给出完整安全归约；测试不能替代安全证明。ABB 同组诚实父/叶/256 bit 新 SamplePre 闭环、Luo 组合、多身份攻击以及正式参数仍为 WIP。
