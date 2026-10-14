# B：Sageloli SIS／RSIS 已完成研究验证批次

这批交付把已在本地跑通的数学探针整理为可重放源码、测试、参数核验及论文映射。**已有真实 Trap／DelTrap／SampleD 采样验证；尚无完整 IBS 公共后端。** 矩阵与环两条方案分开计数，不把一次数学探针算作完整签名服务或安全实现。

源码：[`probe.py`](../../../../experiments/research/candidates/sageloli/probe.py)、[`width_check.py`](../../../../experiments/research/candidates/sageloli/width_check.py)；专属测试：[`test_sageloli_probe.py`](../../../../tests/test_sageloli_probe.py)。本批基于 SRGG 交付的采样工具，PR 依赖对应 SRGG 分支；不包含尚未完成的 Foo–Li 封装。

## 完成范围

| 路线 | 已执行 | 扰动方式 | 范围边界 |
|---|---|---|---|
| 矩阵 SIS | CBD 根陷门、8 列真实 Gaussian 委派、一次 Gaussian 原像采样、根／用户方程与两块范数 | 全局 `prepare_f`：连续数值正态加真实整数 Gaussian 舍入 | H1／H2 使用独立均匀测试目标；未实现身份、盐和消息哈希 |
| 环 RSIS | 结构化 CBD 根陷门、9 个多项式列真实委派、旋转展开、一次相关 Gaussian 原像、方程与两块范数 | 块大小 4 的 `prepare_p` Schur 数值解释 | 未声称全局 Peikert 核的逐字实现或整体分布误差认证 |

运行中检查精确陷门方程、PSD 准入和签名方程；这些检查使用显式异常，在 Python 优化模式下也有效。陪集是有限离散 Gaussian，扰动复用已有有限精度连续正态和离散舍入。没有用均匀向量、公开线性解或只有代数等式替代秘密采样。

只输出公开参数、维数、检查结果与计时；陷门、私有形状／因子、辅助扰动和原像不写入收据。本批固定 RNG 是可重放的测试流，不能作为实际秘密钥随机源。单次本机计时用于确认执行路径，不作安全参数性能排名。

## 原文版本与算法映射

使用 [HAL v1 完整稿](https://hal.science/hal-04107694v1)，归档为 [`papers/2023_shorter_faster_ibs_sageloli.pdf`](../../../../papers/2023_shorter_faster_ibs_sageloli.pdf)，73 页。SHA-256：`0e92f184828bc8643a774e9c334b14689346387981e766c311c596239ef73e3e`。下列均为 PDF 页码，比原文印刷页码大 1；不混用出版社短稿。

| 对象／步骤 | 矩阵版：Figure 5/6，PDF 18/19 | 环版：Figure 7/8，PDF 23/24 |
|---|---|---|
| 公钥 | A：n×m，q=3^k | A：1×l 个 R_q 多项式，R=Z[X]/(X^d+1)，q=3^k |
| gadget | G=[I_n,3I_n,…,3^(k−1)I_n]，digit-major | g=(1,3,…,3^(k−1))；系数展开为相同 G，rows=d |
| 主陷门 | (m−nk)×nk 个整数 | (l−k)×k 个多项式 |
| H1／H2 | n×nk／n 个模 q 系数 | k 个多项式／1 个多项式 |
| 身份陷门 | m×nk 个整数 | l×k 个多项式 |
| 委派调用 | nk 次 SampleD，每次得到一列 | k 次 SampleDR，每次得到 l 个多项式，然后旋转展开 |
| 签名采样输出 | m+nk 个整数，内部保留整数 lift | l+k 个多项式，共 d(l+k) 个整数 lift |

Prop.3（PDF 13）及 Prop.19（PDF 53）要求委派满足 A T_id=B−G。签名阶段仅调用一次 SampleD／SampleDR，**没有消息相关的第二次委派**。

完整的自适应版本发钥时取身份盐 r，B=H1(r,id)，返回 (r,T_id)；每次签名取新消息盐 s，u=H2(r,s,id,msg)，返回 (r,s,z)。Figure 6/8 非自适应版本省略盐，不能与自适应版本混记。以上是后续后端的冻结实现规格；本批探针直接抽取 B 与 u，不声称已经实现这些哈希与盐。

### 三进制采样核

Prop.2（PDF 13）打印的 A=[Abar | G−Abar R] 与其 A[−T;I]=G 定义存在符号冲突。本批明确采取 **存储 T=−R** 的解释，始终构造 J=[−T;I] 并检查 A J=G mod q；不把此解释说成原文已更正。根矩阵 CBD 的零概率为 1/2，±1 各 1/4；环根噪声按照 PDF 9，前、末 d/4 系数为 4P_(1/2)，中间 d/2 系数为 P_(1/2)。

目标宽度平方为 s²，固定舍入宽度平方 r0²=16，扰动形状 Pi=s²I−9r0²JJᵀ。采样前检查 s²I−11r0²JJᵀ 为 PSD；MP12 的三进制 gadget 形状 9I 加 2I 裕量给出常数 11（本库 MP12 PDF 17–19、Algorithm 3 PDF 28）。

先采真实扰动 p，令 v=u−Ap mod q。对于每个 syndrome 系数依次采 x_i∼D_(3Z+(state mod3),3r0)，再令 state=(state−x_i)/3。返回 z=p+Jx。最后 carry 可非零；所需结论是 Σ3^i x_i=v mod 3^k。全流程使用复合模数整数运算，不把 q 当成素数域。

环乘法矩阵第 j 列是 Cf(X^j a)，保证 C(A)Cf(z)=Cf(Az)。原文 Rot 用行列记法产生方向歧义，本批用列作用定义并在测试中验证 X^d=−1、多项式乘法和旋转结构；不独立抽取 dk 列代替 k 个环列。

### 范数与宽度

PDF 8 的模数绝对值使用中心代表元。故最终签名验签应检查中心化 z 的非零、同余式及两块范数：矩阵上界平方为 2m s_sign²、2nk s_sign²；环版为 2dl s_sign²、2dk s_sign²。探针同时检查原始整数 lift 和中心化输出，以区分采样行为与公开验签条件。

| 参数 | SIS | RSIS |
|---|---:|---:|
| n,k,m／d,k,l | 2,4,16 | 4,9,22 |
| q | 81 | 19683 |
| 根／签名系数维数 | 16／24 | 88／124 |
| r0²；epsilon | 16；2^−64 | 16；2^−64 |
| s_id；s_sign | 2^14；2^28 | 2^18；2^33 |

`width_check.py` 用 192-bit 区间运算核验 Table 2/4 的宽度公式及 smoothing r0² 条件，正文 C<38 采用保守上界 38，不使用 Appendix E 的经验常数。Table 4 的 2k+k/2≥l>max(2k,21) 和四分块噪声条件使本例选择 k=9,l=22,d=4。**满足宽度公式不等于安全参数或整个有限采样分布已准入。**

## 已知限制与待完成项

- 两个调试 profile 的 q 远小于签名宽度。所有中心代表元甚至自动满足范数界，收据明确标记 `profile_norm_check_is_vacuous=true`；不能宣称不可伪造或任何安全等级。`security_claim="none"`、`backend_admitted=false`、`complete_ibs_backend=false`。
- 连续 tickets／Box–Muller／有限精度因子及总体 TV 未认证。环版全局 `prepare_f` 在既有 8192-bit rational 资源上限下受阻，本批保留块大小 4 的数值解释，没有放宽或绕过资源检查。
- Figure 1（PDF 11）的 OSign 每次重新 KeyExt／取新 r。固定身份缓存会重复 r；Prop.5（PDF 14）多签 Gaussian 讨论不自动补齐自适应哈希重编程的服务模型映射。
- Lemma 1（PDF 12）、Prop.10（PDF 24）、Prop.21（PDF 54）打印含 −d(2k−l) 的指数，同时 l>2k，使相关项增长。本批保留此疑似反号，不静默改符号继承安全界。
- Prop.19（PDF 53）把 SampleDR 输出写为 R_q^k，与 A 的 l 列及 Figure 7/8 冲突；本批以满足方程的 l 维环输出为实现解释。Appendix E 身份钥计数还包含额外 k 行，既有单位账本不是实测 wire。
- 后续仍需 H1／H2 域分隔与盐、完整四算法／共同五方法、独立参数与规范对象、固定发钥缓存／中止／恢复、wire 容量、错误身份／消息与篡改验收、登记提案、真实 HIBE 组合及参数／模型准入。本 PR 不改变公共注册器、CLI 或默认安全参数。

## 重放与证据

在仓库规定的 WSL conda Sage 环境运行。下面假定当前目录为仓库根；pytest 需安装到该环境，或使用本机已准备的 `.pytest-tmp-sage-deps`（后者是忽略目录，不属于交付依赖）。

```sh
source ~/miniconda3/etc/profile.d/conda.sh
conda activate sage
PYTHONPATH=src python -m experiments.research.candidates.sageloli.probe --kind both --output test-results/sageloli-probe.json
PYTHONPATH=src python -m experiments.research.candidates.sageloli.width_check --output test-results/sageloli-widths.json
PYTHONPATH=src PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest tests/test_sageloli_probe.py tests/test_srgg_full_sampling.py tests/test_candidate_foundations.py --basetemp=.pytest-tmp-sageloli-replay -q
```

本批公开收据为 [`probe-result.json`](probe-result.json)、[`width-check-result.json`](width-check-result.json)、[`sage-regression.junit.xml`](sage-regression.junit.xml)。精确源码／证据散列及实际本机命令见 [`manifest.json`](manifest.json)。测试覆盖全 81 个 syndrome 的 gadget 原像、同 syndrome 新鲜 Gaussian、负号与环乘法方向、错误陷门／不足宽度拒绝、两套完整数学链及参数公式；测试成功仍不能替代安全证明。

2026-10-13 最终相关回归：**62 passed，0 failed，0 skipped**（Sage 10.7／Python 3.12.13，26.38 秒），包含 10 项新专属测试和既有采样／基础包回归。另一次公开 CLI 重放中，矩阵数学链约 0.164 秒，环约 15.54 秒；环用户计划构建约 13.31 秒。这些单次执行同时与测试进程运行，不作独立公平性能基准。独立只读复核另跑新测试 10 passed；计数与上述 62 项交叠，不相加。
