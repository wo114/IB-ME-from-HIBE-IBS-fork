# SRGG 原论文参数基线：来源与实现对应

日期：2026-10-16。本文记录直接原论文参数复现的选定解释，不为旧优化候选补写安全证明。

## 1. 固定来源与阅读范围

Jia、Liu、Tang、Wang，*Constructing Efficient Identity-Based Signatures on Lattices*，
[DOI 10.1049/ise2/6684889](https://doi.org/10.1049/ise2/6684889)。
仓库原稿：[2025_efficient_ibs_jia.pdf](../../../../papers/2025_efficient_ibs_jia.pdf)。
固定 SHA-256：`258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。

本次定向核对 PDF 实际第 3 页 §2.2、第 5 页 §4.1–4.2、第 6 页 Table 3、
第 7 页 Algorithms 1–6、第 8 页 Algorithms 7–8、第 9 页 §5.1、
第 10 页 Tables 4–7。不声称重新核验全部引用论文或完成全文安全证明审计。
本文只转述实施条件与参数事实，不全文抄录算法。

Gaussian 记号另核 Peikert，*An Efficient and Parallel Gaussian Sampler for Lattices*，
[本地作者稿](../../../../papers/2011_peikert_parallel_gaussian_author.pdf) §2.4，
SHA-256：`39ae6ea450a98267ab7f3ac682e4daae4a91ec8aed9432dca666e05eefd46163`。
该稿明确将实际协方差乘 `2π` 后的矩阵简记为 covariance；引用这一约定不等于
作者已确认 SRGG Table 4 的具体数值解释。

## 2. 固定三组输入

三组共同采用 `n=512,p=16383,b=31,w=2,q_gadget=31²=961,Q=p·q_gadget=15744063`，
CBD1 陷门系数分布、`Q_s=2^40`，以及原文报告的近似值 `r≈1.16`。
代码用精确十进制 `1.16` 表示这个报告值；它不是对 smoothing parameter 的精确求值。

| Table 4 输入 | PARAM-I | PARAM-II | PARAM-III |
|---|---:|---:|---:|
| 模块秩 d | 2 | 3 | 4 |
| msk 报告标准差 σ1 | 2843.9 | 3399.4 | 3867.7 |
| msk 报告标准差 σ2 | 1023.0 | 1065.3 | 1089.9 |
| 签名报告标准差 σ̄1 | 843088.2 | 1046714.2 | 1238066.0 |
| 签名报告标准差 σ̄2 | 310891.6 | 384614.5 | 448859.2 |
| 签名验收上界 γ | 42086491.7 | 63653172.0 | 86573930.5 |

这些是来源参数，不继承作者报告的安全位数或本项目正式准入。
γ 的验收采用精确整数平方比较，阈值为 `floor(γ²)`。

## 3. 两种 Gaussian 记号

代码统一以 `exp(-π(x-c)^T Σ^-1(x-c))` 定义 density shape。
相应连续 Gaussian 的实际协方差为 `Σ/(2π)`；离散 Gaussian 的实际二阶矩
一般也不能直接写成这个连续协方差。

| 显式 interpretation | 如何读取表中数值 s | 内部 density shape |
|---|---|---|
| `table-standard-deviation`，默认 | 将 Table 4 标为 Std. dev. 的数值及报告 r 视作物理标准差 | `2πs²` |
| `literal-density-width` | 将相同字面数值视作 §2.2 的 density width | `s²` |

默认解释与 Table 4 的列名相符，但**未获作者确认**；两个模式均记录解释、
原稿指纹、`r=1.16` 的近似性质及 π 的有限精度约定。
`paper_parameters.py` 以 512 bit 定向区间固定 π 的有理近似和误差说明，
不把有限近似说成精确超越数实现。不同 interpretation 产生不同 public context，
恢复和解析时不得互换。

两种解释是归一化敏感性检查，不是两种新密码方案。默认解释下，
`r_density=√(2π)·1.16`；这里不会再替换为旧候选的 `r²=64`。
沿用原稿数值不表示其所有 smoothing、归约或安全条件已经满足。

## 4. 原文到代码

下列入口都在 `experiments/research/candidates/srgg/`，与旧优化路径分开。

| 来源位置 | 本基线中的对应 | 实施约定或边界 |
|---|---|---|
| §5.1 / Table 4 | `paper_profiles.py`、`paper_parameters.PaperParams` | 保留三组原始小数、w2、Q 和 γ；不调用旧 conditional-candidate gate |
| Algorithm 1 / Table 3 | `paper_backend.Backend.setup`、`paper_algebra.PaperRing.build_public` | CBD1 R、公钥陷门关系、非正扰动形状时的原文 setup repeat；设置显式运行次数上限，耗尽则中止 |
| Algorithms 3–4 / Table 3 | `paper_samplef.PaperSampleF`、`structured_geometry.master_operator` | 使用表中两段 anisotropic shape；有限 joint sampler 近似所声明的目标离散 law，数值机制与原文逐层 Schur / 作者 C 实现不同 |
| Algorithms 5–6 | `paper_backend.PaperGadget`，复用真实 Gaussian coset recurrence | 逐系数保留近似 gadget 关系；remainder 明确用 centered-mod-p 代表；有限核不是作者 table-based sampler 的逐随机位复现 |
| Algorithm 2 / §4.2 | `Backend.key_extract`、`SigningKey` | raw 近似逆像后保存 tail；不额外施加旧 raw/user norm cap，不因未达旧 cap 重新发钥 |
| Algorithm 7 lines 1–2 / HNF | `PaperRing.reconstruct`、`SigningKey.full` | 由 identity target 和 tail 恢复头部；采用明确记录的 `centered-mod-Q` 代表，原文未固定这一模代表选择 |
| Table 3 / Algorithm 7 | `signature_operator(..., noise_factor=1)` | 保留表中文字面的 factor1，以及两段 signature target；不偷偷替换为旧 factor2 解释 |
| Algorithm 7 lines 9–10 | `PaperRing.zeta/response`、`Backend.sign` | `ζ=1+X^(n/2)`，`u` 的中心 `-c/ζ=-(ζ*)·c/2`，其中 `ζ*` 为共轭；响应按原方程计算 |
| Algorithm 7 lines 11–13 | `Backend.sign` | 仅签名范数超 γ 时按原文重试；运行次数上限是单独的工程限制，不调高 γ 来获取成功 |
| Algorithm 8 | `Backend.verify/load_signature`、`PaperRing.recover` | 2Q 承诺恢复、完整二进制 challenge、规范对象和 context/身份/消息绑定检查 |
| 公共五方法 / 恢复 | `paper_objects.py`、独立固定发钥服务 | 工程接口与持久状态扩展；其状态一致性测试不替代原文安全归约 |

Table 3 的 signature target 为 `σ̄1² I_(2d) ⊕ σ̄2² I_(wd+1)`；
**没有额外首块 `ζ^-1` diagonal**。`ζ^-1` 出现在 u 的中心，
`j=(ζ*,0,…,0)`；原文矩阵的首块是 `2I_d`。

**Gadget 的模代表约定。** §4.2.2 只称 `e∈Z_p` 为 small error，
Algorithm 6 写 `e=u mod p, v=(u-e)/p`，未指定整数代表区间。
本实现明确选择 `e∈[-floor(p/2),floor(p/2)]`，随后用同一 e 精确计算 v；
`gadget_remainder_representative=centered-mod-p` 写入参数记录。
这不改变 p、Q、Gaussian 宽度或模同余方程，也不声称是作者唯一规定的 lift。
它与 sign 时头部采用 `centered-mod-Q` 是两项分别记录的约定。
首次使用 unsigned remainder 后发生的执行失败保留在 ignored
`build/outputs/srgg-paper-baseline-2026-10-16/preliminary-unsigned-remainder-PARAM-I.json`
和 `preliminary-unsigned-remainder-PARAM-II.json`；不将这些失败收据覆盖成成功。

## 5. 保留的已知差异与限制

**ζ 的 factor1/factor2 疑点。** 系数 Euclidean 算子满足 `Mζ Mζ^T=2I`，
而 Table 3 的签名扰动减去字面 factor1。本基线保留 factor1 作为原文复现选择，
明确记录该疑点；不声称据此继承完整离散卷积分布、HVZK 或 strong 证明。
旧 factor2 优化和全部既有审计材料保留，不覆盖、删改或混称为本基线的证据。

**发钥与运行失败。** 原文的 KeyExt 没有额外 raw/user norm cap；
固定身份缓存、`pending/failed/issued`、文件锁、原子写和异常后阻断属于工程包装。
运行预算、256 bit 系数 guard 和 2 MiB wire 界是资源限制；失败必须明确返回，
不能用换 root、换身份密钥或修改表中宽度来隐藏。

**尺寸与性能。** 原文 sk/签名尺寸是 ANS 熵编码口径，计时是作者 C 环境结果。
本基线的规范 JSON/wire、有限 Gaussian 内核及 Python/Sage 时间分别报告；
未实现或未验收 ANS 前不把原文尺寸写成本机输出，不把一次运行与作者 C benchmark
当作同实现公平速度比较。

**安全口径。** 原文 Theorems 1–2 是安全论证来源，但当前的记号解释、有限采样、
HNF/固定服务、游戏及参数对应仍按已有审计单独列明。本复现不承担新的完整
QROM/native-strong 归约，不把诚实运行和有限攻击拒绝升级成密码学安全证明。
统一保留 `security_claim=none`、`backend_admitted=false`、
`parameters_are_formal=false`、`nist_security_category=null`。

## 6. 已封存的实际交付

实现提交为 `e9736f28ba907be28ca0bf13a27b9e67187b0bab`。
三组、两种解释的六轮测试生命周期，以及一轮 PARAM-I 系统随机数生命周期均完成；
221 项互异测试通过。收据、环境、参数、尺寸、时延及限制见 [README_zh-CN.md](README_zh-CN.md) 与 [validation.json](validation.json)。
II/III 默认解释的真实样本出现同消息 Q 平移替换成功，不能宣称 native strong；
普通 fresh-message EUF、最终分布和正式参数对应仍需独立判断。
有限误差界有退化为 1 的项目，不冒称复现论文 epsilon。
旧优化完整保留，仅本地提交；完整安全/参数准入与 ANS/C 复现尚未完成。
