# SRGG 精确环形状算子：扩维组件

日期：2026-10-16。实现：
`experiments/research/candidates/srgg/structured_geometry.py`；
测试：`tests/test_srgg_structured_geometry.py`。

**已实现和实测的是形状线性算子，不是新的 Gaussian sampler、完整 n=512 IBS
后端或安全参数。** 原有 backend、wire、`Params`、采样器及其资源上限没有修改。
模块在 `QQ[X]/(X^n+1)` 中执行精确运算，不生成 n×n 系数算子或完整形状矩阵。

## 与现有形状的精确对应

记 V 为 master 的 R，或签名的完整用户向量 y 单列。
设 α 为 shape noise_squared：master 是 `b²r²`，当前 factor2 签名解释是 `2r²`。
令 β=`second_squared`，D 为 top 的逐环分量对角，T=`[V;I]`。
实现的是当前 `geometry._geometry` 同一个表达式：

```text
Σp = diag(D, β I) - α T T*
   = [ D - α V V*       -α V    ]
     [ -α V*           (β-α) I ]
δ = β-α.
```

保留了非等宽目标：master 的 D 全为 `master_first_squared`；
signature 的 D 前 `2d` 个环分量为 `signature_first_squared`，
其余 `wd` 个为 `signature_second_squared`，另一个 lower 分量也为 second。
不能把签名的整个 top block 强制改成一个 first_squared 标量。

公开的方法与公式：

| 方法 | 精确作用 |
|---|---|
| `v_apply` / `v_adjoint_apply` | V 与 V* 的 matvec |
| `factor_apply` / `factor_adjoint_apply` | `[V;I]` 与其 adjoint 的 matvec |
| `perturbation_apply` | Σp 的完整 matvec |
| `conditional_apply` | `(D-αβ/δ·VV*) upper` |
| `conditioned_center` | `-α/δ·V lower` |
| `shifted_schur_apply` | `(D-r²I)-α(β-r²)/(δ-r²)·VV*` 的 matvec |

所有多项式乘法使用 Sage 的精确 QQ 多项式运算后模 `X^n+1`。
这里的形状计算不做模 Q 约简。Adjoint 的环共轭为
`f*(X)=f0-Σ_{i=1}^{n-1} fi X^(n-i)`，与负循环系数算子的转置相对应，
不是只转置模块行列。

构造时检查 `δ>r²`，使 lower 的 scalar margin 与 shifted-Schur 分母有效。
**这不等于检查整个形状正定**；组件没有执行全形状 LDL 或新的正定准入。
`full_positive_definiteness_checked=false`、`sampler_implemented=false` 在 metadata 中明确保留。
小维度测试的旧 dense geometry 另外执行了实际 exact-LDL；
那是对应夹具的核对，不是新组件对任意输入的正定证书。

## 实际精确核对

指定 WSL `~/miniconda3/envs/sage`，Sage 10.9：
**17 passed，0 skipped**。

在 n=2/4/8、不同模块秩和 gadget 位数上，master R 与 signature y 均非零，
宽度 first/second 不同；signature 使用 factor2。
对每个方法的完整标准基，以及一个非平凡整数向量，逐项比较新算子输出与原有
`master_geometry/signature_geometry/module_operator` 的精确系数矩阵结果。
覆盖上表全部八种作用，也覆盖共轭 adjoint 内积一致性、factor1/2 区别、
有理系数、CBD1 支持、维度与资源拒绝。

比较时显式把 Sage QQ 的 numerator()/denominator() 转为 Python 整数再构造 Fraction，
避开当前 Python 3.13 `Fraction(SageRational)` 对方法属性的兼容问题。
比较未使用浮点容差。

## n=512 实体算子测量

实际运行 `n=512,d=2,w=8`，master 见证为公开确定性 CBD1 支持系数模式，
signature 见证是公开小整数向量模式，**不是由 Setup/Extract 产生的密钥**。
宽度取 `formal_candidates.conditional_candidate` 同一个条件研究点。
每个方法测量一次，没有身份、消息或签名采样。

平台为 WSL2 Linux、Sage 10.9、conda-forge Python 3.13.15，
Intel Core Ultra 7 255HX；没有固定 CPU 频率、亲和性或后台负载。

| 实测项 | master | signature |
|---|---:|---:|
| 对应完整系数维度 | 10,240 | 10,752 |
| 若展开完整形状的条目数（未展开） | 104,857,600 | 115,605,504 |
| 存储的 V 多项式数 | 64 | 20 |
| 另存的 V* 多项式数 | 64 | 20 |
| V 与 V* 的系数 slots | 65,536 | 20,480 |
| 构造秒 | 0.08987 | 0.02162 |
| `v_apply` 秒 | 0.01347 | 0.00251 |
| `v_adjoint_apply` 秒 | 0.00482 | 0.01247 |
| 完整 Σp matvec 秒 | 0.04549 | 0.03802 |
| conditional matvec 秒 | 0.00995 | 0.01533 |
| conditioned center 秒 | 0.01073 | 0.00382 |
| 本公开见证与 adjoint 的 pickle 字节 | 591,989 | 185,360 |
| 多项式浅层对象 getsizeof 字节 | 13,312 | 4,160 |

worker 在夹具前 `ru_maxrss=210736 KiB`，两个阶段记录到的高水位均为
`230124 KiB`。RSS 包含 Sage 导入、两个阶段的临时运算、输出校验摘要和
公开 fixture 的 pickle 测量；不是单份矩阵或堆的大小。
浅层 getsizeof 不覆盖所有原生系数分配，pickle 也不是实际 wire 或常驻内存估计。
不能把这些字节数字当作完整 IBS 内存。

此次没有运行大维度 dense 对照，没有测量该对照的时间，
因此没有给出时间加速倍数。完整 shape 条目和实际存储的低秩因子 slots
是不同表示的明确计数；保留低秩表示使这次 n=512 matvec 可以实际执行，
并不表示同维 Gaussian 抽样已实现。

## 资源门与待完成边界

资源门为 n≤4096 且为二次幂，module rows/columns≤128，
输入 witness 系数 slots≤`2^20`，输入系数和宽度为精确整数/有理数，
其 numerator/denominator 至多 4096 bits。
master factory 另保留当前 CBD1 支持和奇数 gadget base 条件。
见证与 adjoint 会各存一份，多项式运算还需要临时对象。

**MAX_RATIONAL_BITS 只是输入门；不是中间多项式、Schur 结果分母增长或
全路径堆内存的证书。** 后续精确乘法、加法和缩放可能增长有理位数。
组件不保证所有门内输入都能在某个统一时间、堆大小或输出 bit 预算内完成；
也不称“全资源可准入”。本次结论限于指定公开夹具的实际执行。

要把该组件用于真实后端，仍需形状正定/分解契约、结构化连续采样与 Gaussian rounding、
连续 ticket 和精度误差证书、scalar 大宽度预算、HNF 密钥分布及失败条件对应、
对象/恢复/攻击生命周期，以及困难性和 strong premise 核对。
没有把新表示作为新的密码方案，也没有改变原方案采样语义来声称扩维完成。

## 复现与证据

本地证据：`build/outputs/srgg-admission-2026-10-16/structured-geometry.json`，
以及同目录 `structured-geometry.stdout.json`、`structured-geometry-tests.junit.xml`。
JSON 保留源码 SHA-256、完整测量、输出校验摘要与公开配置；没有输出见证内容。
build 为本地输出，跨机器移交须另行打包或复现。

```sh
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_structured_geometry.py \
  --junitxml=build/outputs/srgg-admission-2026-10-16/structured-geometry-tests.junit.xml

PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.structured_geometry \
  --output build/outputs/srgg-admission-2026-10-16/structured-geometry.json \
  > build/outputs/srgg-admission-2026-10-16/structured-geometry.stdout.json
```

本实验没有 ROM/QROM 证明或安全等级结论；所有安全标志保留
`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。
