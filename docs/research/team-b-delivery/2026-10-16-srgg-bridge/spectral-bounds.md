# SRGG：确定的公开谱界与有序 kernel-GSO 界

日期：2026-10-16。本项不改变参数、setup 分布、采样器、对象或 `psf_bridge.py`。全部界为精确有理数；不运行 FFT、不读私钥、不使用数值特征值。状态保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。

## 1. 实系数负循环算子的通用半 trace 界

令 n>=2 为二次幂，R 为 r×c 个实系数、多项式次数小于 n 的矩阵，M(R) 为普通系数内积下的负循环展开算子。令 `E=sum_(i,j,k) R_ijk²`。

负循环 Fourier 变换是复数域中的酉变换，将 M(R) 分解为 n 个 `R(ω_l)` 块，`ω_l=exp((2l+1)πi/n)`。实系数保证共轭两个根的矩阵共轭，所以两块的奇异值完全相同。n 为偶数，这些根均非实，因此每个最大奇异值至少出现两次。又有 `||M(R)||_F²=nE`，故

```text
||M(R)||_2² <= nE/2,
||[M(R);I]||_2² <= 1+nE/2.
```

这是确定性界，不要求随机系数或“通常的矩阵”。若调用方固定公开 energy cap `E<=U` 并在私下逐系数验证，就可使用公开 class 界 `β=1+nU/2`，metadata 只需输出该 cap 与 β。若只是从某一根私钥算出实际 E，则结果是 **per-root 鉴证**，不是整个 setup 支持类证书；不应将秘密 aggregate norm 当公开遥测导出。

该结论也适用于签名见证列 y：若已有完整用户系数范数 cap U，`||[M(y);I]||²<=1+nU/2`。它不证明用户范数 cap 的成功率或密钥分布。

## 2. CBD1 整个支持类的更紧界

若每个系数属于 `{-1,0,1}`，对单个多项式 a，有更紧的确定性界

```text
max_l |a(ω_l)| <= csc(π/(2n)).
```

证明：固定根 `ω_l`。因 n 为二次幂，`2l+1` 与 n 互素。其前 n 个方向模 π 后恰为间距 π/n 的 n 条直线；允许实系数 `a_k∈[-1,1]` 形成的平面 zonotope，与这些等距线段生成的 zonotope 相同。沿任意支撑方向的极点将 n 条直线的符号选到同一个开半平面；按角度排序后，是 n 个相邻、间距 π/n 的单位向量之和。因此每个非退化极点的长度均为

```text
|sum_(j=0)^(n−1) exp(ijπ/n)| = 2/|1−exp(iπ/n)| = csc(π/(2n)).
```

退化支撑边上的点也不会越过其端点最大范数。凸函数范数在该多面体的最大值取于极点，结论成立。这个论证覆盖整个实区间盒，因此当然覆盖 CBD1 离散支持。

对每个频率，矩阵平方谱范数至多其 r×c 个 entry 平方模之和，得到

```text
||[M(R);I]||² <= 1+rc*csc²(π/(2n)).
```

作为整个支持的解析上界，这个常数实际上可达：选实现极点的同一个 ±1 多项式填满所有 entry，则某频率块为 rank-one 的全 1 矩阵乘该多项式值。故不能在不加概率／能量等额外条件时任意继续大幅压低这个类界。

实现不计算三角函数。取由已证明 Machin 有理下界向下截成 64-bit dyadic 的 `π_low`，令 `x=π_low/(2n)`。因 sin 在相应区间递增，且 `sin x>=x−x³/6>0`，有

```text
csc²(π/(2n)) <= 1/(x−x³/6)².
```

向上舍入成 128-bit dyadic 后，与第 1 节的单 entry 上界 `n²/2` 取最小值。n=2 时后者精确，n512 时所选界接近 `4n²/π²`。对 SRGG 的 `r=2d,c=wd`，它把旧 `1+2d²wn²` 缩为约其 `4/π²≈0.405285`。没有使用矩阵分布浓缩，也没有重抽 setup，因此这项改进不引入新的 setup conditioning 损失。

API：`public_support_class_bound(degree=n,rows=r,columns=c)` 返回 `t_spectral_squared_upper_exact` 和 `scalar_polynomial_spectral_squared_upper_exact`（精确 Fraction 字符串）。`public_t_squared_upper(n,d,w)` 直接返回 SRGG class 的 Fraction。调用真实 witness 时仍须先检查其每个系数是精确整数且位于 CBD1 支持；class API 自身不接收／认证任何私钥。

## 3. kernel 基的顺序消除旧 middle 列长项

沿用 `psf_bridge.exact_kernel_basis` 的完整基和已证明的 kernel/index 关系，按其现有顺序：全部 gadget 列、全部 first-head 列、全部 middle 列。设 `H=dn,m=wdn,T=[R;I]`，公开 `||T||²<=β`。

1. gadget 列是 `T B_g`，其中 B_g 为满秩 gadget kernel 基，列形如 `b e_i−e_(i+1)` 或 `b e_last`。它们的 span 恰为 `im(T)`，每列长度平方至多 `β(b²+1)`，因此其 GSO 长度也有相同上界。
2. head 列写成 `p e_j+Tz_j`。前 m 列已经张成 `im(T)`，后项在 GSO 投影后完全消失；残差范数至多 p。加入 H 列后，前缀的 span 是 `im(T)+first-head-space`。
3. middle 列写成 `e_middle + head_residue + Tz`。两项后缀都落在前缀 span 内，投影后只剩 `e_middle` 的投影，范数至多 1。真实未投影 middle 列可以很长，不影响这个 GSO 结论。

所以对**同一现有基**，无需换协议或运行格约简，便有

```text
max_i ||b_i*||² <= max{ β(b²+1), p², 1 }.
```

旧版以原始 middle 列长度估计 GSO，含 `2β*((b−1)/2)²*m` 项；该项在上述顺序中没有必要。API `ordered_kernel_gso_bound(p=...,base=...,witness_spectral_squared_upper=β)` 给出新界；β 必须来自已核验 class 或已检查 root。它不修改 `psf_bridge.py`，后者可由其负责人在审查证明后接入。

## 4. 原 n512 三个候选的筛查

输入仍是 `formal_candidates.conditional_candidate(rank=d)`：n512、b31、w8、r²64，所有 master/signature widths、Q 和 caps **不变**。下表只读调用当前 C 与 PSF 证书函数；未构造 n512 根、矩阵或签名。

| d | 新 C 最小特征值下界（显示） | C 平滑充分条件 | 采用有序 GSO 的 coset 平滑 | `noise*β/(master_min−r²)` 上界（显示） | 原 zero-center reference 的修复 TV 上界（显示） |
|---:|---:|---|---|---:|---:|
| 2 | 36577.28729988 | 通过 | 通过 | 0.4052860415854 | 0.7298275544234 |
| 3 | 36577.28851021 | 通过 | 通过 | 0.4052860218925 | 0.5959017127302 |
| 4 | 36577.28893383 | 通过 | 通过 | 0.4052860149999 | 0.5160660243768 |

旧 C 下界分别低于 1，因使用最坏 Frobenius 界、宽度仅比其正定门多出很小 slack，而没有识别负循环实结构。本项证明给出严格更紧 class 界，故**这些旧参数的 C 充分条件现在能核验**；不再需要仅为 C 擅自整体扩大 master width。这并未使所有参数、安全归约、norm／abort 或实际大维度生命周期自动通过。

kernel 平滑的改善来自第 3 节有序 GSO，而不是假定实际私有基很短。仅用旧 Frobenius β 配合该有序 GSO，也已比旧 raw-middle 列界紧得多。新 β 又进一步改善它。

最后一列仍然很大：当前 PSF reference 选择的是 zero-center exact-fiber Gaussian。近似误差 e 修复为 `Y=U+Je` 后，该 reference 的通用 Hellinger 位移界没有因 kernel 平滑而消失。本项没有把约 0.5–0.73 的单次界当作可接受的多查询安全误差。

**已证明的另一参考：** [mixed-domain.md](mixed-domain.md) 将全局 SampleDom 域 law 定义为先取固定公开 Gaussian U，再独立均匀取 `E∈[0,p)^H`，输出 `canonical_head(U+JE)`，forward 仍取 `AY mod Q`。该材料已证明这个全局 reference 的条件 law 与修复后的理想 union law **严格相等**，并证明像近均匀性的继承；同时明确 norm／abort 条件化和条件熵所需前提。它避免将输出逼近不匹配的 zero-center reference，但原文 Gaussian-secret SIG、one-wayness、现有参数的熵／失败预算及全局安全对应仍未完成。

## 5. 复现、测试和边界

```text
python -m pytest -q tests/test_srgg_spectral_bounds.py
python -m experiments.research.candidates.srgg.spectral_bounds --output build/outputs/srgg-bridge-2026-10-16/spectral-bounds.json
```

测试独立检查 n4 全部 81 个 ternary 多项式的精确谱式、n2 可达等号、非 CBD 私有 energy 与公开 class 的分离，以及小参数实际完整 kernel 基的逐阶段 exact GSO。它们补充实现证据，一般谱／GSO 界依赖前文证明。

本项不建立 source 归约、strong／CUR／UF-NMA、NIST 等级、统计最优性或大参数运行能力。私有 energy 接口只用于明确输入的 root 鉴证；真实服务不应为研究 telemetry 导出 norm。若采用概率谱界或改变 setup 筛选，仍须另外计入分布变化，本项确定性 class 证书不作此变化。
