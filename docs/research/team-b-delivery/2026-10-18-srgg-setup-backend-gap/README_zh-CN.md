# SRGG 原表 Setup 后端差距：零原子诊断（WIP）

这是比较原论文数学正定条件 `A` 与当前 source-Schur 后端实际成功条件
`B` 的**第三条、也是最后一条有限路线**。直接证明 `A ⇒ B` 缺少覆盖全部
正根的有限精度论证；缩小谱阈值后再用矩界的路线，先要证明阈值内的根一定
通过区间、叶下界、增益与资源检查。本路线只认证一个可计算原子，到此停止，
不把单个成功根推广为全部正根。

原表三行均为 `n=512、w=2、d=2/3/4`。令 `M=(2d)(wd)n`，对应
`8192/18432/32768` 个独立 CBD1 系数。每个系数取零的概率为 `1/2`，
所以全零陷门概率恰为 `2^-M`。全零陷门的 Fourier 算子范数是零，严格满足
原论文 Algorithm 1 的数学正定条件。[六行回执](setup-backend-gap.json)
还对两种明确的高斯宽度解释，逐一用全零 32 字节公钥种子和全零陷门字节
重放**完整** `SourceSchurBackend.setup`；六行均一次成功并完成公钥序列化。

在独立均匀源字节、无外部机器故障的前提下，可以严格写出：

`Pr_R[A ∩ ¬B_计划准备] ≤ 1−2^-M`，
`Pr_{种子,R}[A ∩ ¬B_完整首尝试] ≤ 1−2^-(M+256)`。

这些上界虽然严格小于 1，却**非常接近 1，没有实际安全预算价值**。
Setup 只在开始抽一次种子；区间不定、叶下界、增益误差或资源预检产生的
非几何异常会直接终止，而非继续 64 次重抽。因此不能把完整首尝试的失败
界直接取 64 次幂。全部数学正根的一致数值接受界、数值故障概率以及完整
故障／历史分布仍为 `null`。这不是 IBS 安全归约、正式参数准入或 NIST 等级。

论文依据为仓库冻结的 Jia–Liu–Tang–Wang《Constructing Efficient
Identity-Based Signatures on Lattices》，Algorithm 1 与 Table 4，
[`papers/2025_efficient_ibs_jia.pdf`](../../../../papers/2025_efficient_ibs_jia.pdf)，
SHA-256 为 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。
参数宽度未改动；本诊断不涉及 HIBE、身份、消息、签名查询或 ROM 安全归约。
每行只运行一个确定性原子，不能作为性能评测或随机成功率估计。

在仓库根目录的指定 WSL Sage 环境运行：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_setup_backend_gap.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python docs/research/team-b-delivery/2026-10-18-srgg-setup-backend-gap/verify_delivery.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -O docs/research/team-b-delivery/2026-10-18-srgg-setup-backend-gap/verify_delivery.py
```

[验收记录](validation.json)与[字节清单](MANIFEST.json)用于核对交付。清单覆盖本诊断模块、直接使用的 SRGG 源及若干跨包依赖，但不自称穷尽所有 Python/Sage 导入源码；实际六行运行还由验证器重新执行比较。
安全字段固定为 `security_claim=none`、`backend_admitted=false`、
`parameters_are_formal=false`、`nist_security_category=null`。
