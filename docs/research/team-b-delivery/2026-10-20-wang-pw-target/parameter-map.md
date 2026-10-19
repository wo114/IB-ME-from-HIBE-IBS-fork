# Wang–PW s0=4 参数与论文对应

本表固定 Wang 等 ePrint 2022/1718 仓库论文版本：`papers/2022_identity_matchmaking_wang.pdf`，PDF 第7–8页 Lemma 2.5–2.7、第16页 Figure 4 与 Parameter Selection、第17–19页 Theorem 5.1/算法B；外层采用已有 Pan–Wagner ROM 转换与固定发钥服务语义。按当前 AGENTS 引用所选论文，不另开基础安全证明。以下有限工程选取不冒充原文给出的数值参数表。

## 原文、工程参数与历史探针

| 项 | 本档约定 | 来源与限制 |
|---|---|---|
| 主档 | `n=512,q=4294967291,k=32` | q 是实际32位素数，**不是** `2^32`。不是作者给出的128位参数表。 |
| 维数 | `w=n*k=16384,m_bar=w,m=32768,M=m+w=49152` | 满足原文 `m>=2n ceil(log2 q)`。m为公钥A列数，M为签名长度。 |
| 根宽度 | `s0=root_width=4`，`sigma_root=4/sqrt(2*pi)` | `rho_s(x)=exp(-pi*x²/s²)`；真实离散高斯使用此宽度。PR67 `normal(0,4)` 中4是连续正态标准差，还经过舍入，其旧计时/范数不能直接当作本档结果。 |
| root GS门 | `4*ceil(sqrt(w))=512` | 工程接受门；不是所有可能根满足它的定理。超门不得沿用原签名界，应按明确预算重试或失败，并记录。 |
| GPV有限乘数 | `smoothing_multiplier=8` | 指高斯宽度/GS上界，不是normal标准差/GS。每坐标实际标准差仍除以 `sqrt(2*pi)`。 |
| 委派宽度 | `s_del=8*root_gs_limit=4096` | 每列陪集采样宽度。**没有额外乘sqrt(m)**；sqrt维数因子属于样本向量范数或X谱范数估计。 |
| 用户basis GS门 | `user_gs_limit=64*w=1048576` | 独立工程门，检查由用户X构造的basis；不得用主basis GS冒充用户basis GS。接受率待真实运行记录。 |
| 签名宽度/验签界 | `s'=8*user_gs_limit=8388608`，`B_verify²=s'²*M` | 在生成签名前固定。验签使用整数平方范数，不依赖一次样本的范数，也不在加载时重新估计阈值。 |
| 有限采样 | MPFR精度256 bit、概率质量整数192 bit、截断半径20个标准差 | 实际实现与累计误差另给回执；精度数字本身不是已认证的整链误差。每次Gaussian拒绝预算4096。 |
| PW外层 | 身份盐、消息盐、内部身份哈希及内部消息哈希均256 bit | 四个预言机域分隔，外层盐与基础H1/H2职责分开；不得认为256位字段直接赋予IBS 256位安全性。 |
| debug档 | `n=2/4`，q允许17/257或主档q，根宽度仍4，其他维数按同式派生 | `small_params()`默认n2/q257，仅运行真实算法与负例，不用于安全强度结论。小模数下不声称签名阈值满足SIS非平凡性。 |
| 失败与资源 | Setup/Extract/Sign默认各1次，threads16 | 失败明确报告，无隐式重抽。完整快照包含threads；独立`math_context`排除线程数，便于线程调度不改变数学哈希域。 |
| 固定安全元数据 | `none/false/false/null` | 分别为security_claim、backend_admitted、parameters_are_formal、nist_security_category。 |

乘数8的有限工程参考是普通一维平滑充分界
`eta_Z(epsilon) <= sqrt(log(2+2/epsilon)/pi)`：给每次坐标抽样分配误差后，再检查实际调用总量与目标预算。它不是根公钥近均匀性的证明，不替代原文G-trapdoor前提，也不认证MPFR尾部/CDF误差。根采样、委派、签名、重试各自的抽样量与累计预算应以最终引擎回执为准。

## 用户密钥与采样basis

本档的根公钥为 `A=[Abar | G-Abar*R]`。真正发钥应对每列执行

```text
X_j <- SamplePre(A, master_trapdoor, (G-H1)_j, s_del)
A*X + H1 = G
F_id=[A|H1],       F_id*[X;I]=G
```

只把用户G-trapdoor X、公钥与身份/参数上下文交给用户。原型中的
`T_id=[[B_master,X],[0,I]]` **不能作为用户密钥交付**：它包含完整主陷门basis，可用于其它身份。虽然按先B后X的列序，其精确GS确为 `diag(B_master_star,I)`，这个代数事实不能使泄露主basis的密钥成为有效IBS实现。

用户签名可以用 `private_root_basis(A,X,q)` 从**公开A和自己X**建立F_id的basis。构造式正号需保持一致：`H1=G-A*X`，所以builder的第二块正好重建H1。用户从自己的X还可构造短particular `[X*d;d]`，其中`G*d=H2`。这个过程不需要主R或主basis。签名的平滑条件必须针对该用户basis或用户G-trapdoor重新核对。

完整basis GPV是本档选定的有限采样实现路线；原论文的DelTrap/SamplePre以G-trapdoor描述。代数关系和参数约定如上公开保留，不能把仅有方程成立写成分布已等同原文。原文已有条件由引用与实现条件表对应，不另行启动完整安全归约任务。

## SIS输入不能来自一条实测签名

原文第18页提取

```text
z_SIS=[I_m | Rhat] * (z_forged-z_reference).
```

因此输入根SIS时仍为 `(n,m,q)`，不是盲目把m替换为签名长度M。若已有统一上界 `L_Rhat`、`B_reference`，可按原文不等式使用

```text
beta_SIS = ceil(sqrt(1+L_Rhat²) * (ceil(B_verify)+B_reference)).
```

`params.reduction_sis_parameters(...)` 只做这项整数上界换算，不提供缺失的统一谱范数界或分布定理。输入是经说明的统一界，不能填一条根/签名的实测范数。若 `beta_SIS>=q`，`q*e_i` 已是平凡SIS解，正式参数候选应拒绝；研究功能实验仍可进行并保留安全元数据。本档没有据此声称通过123.5或128 bit目标。PR67的单样本estimator数字不能迁移成本档结论。

冻结正式候选前仍需：实际采样与用户GS门回执；有限精度/截断/尾概率和调用总量；原文模拟矩阵谱范数界的来源映射；按正确beta、根列数m、固定estimator版本/成本模型/全部有限攻击重估；公开失败/重试预算及多根资源实测。这里只核对论文前提、参数与实现，不另补安全性证明。

## 廉价参数审计入口与当前数值结果

`src/ibme/ibs/wang_pw_target/parameter_audit.py::audit(params, measured=None)` 不生成矩阵、不运行estimator、不联网、不下载安装。它输出参数来源、宽度单位、两种维数、公开范数阈值、论文SIS界映射、编码长度、内存规划以及未认证项。`measured`中的签名范数和旧estimator位数仅列观测，不进入安全准入。

主档的精确整数验签平方阈值为 `3458764513820540928`，向上整数范数界为 `1859775394`。真实论文SIS β仍为null：当前没有同时交付有来源的统一参考签名范数界与模拟Rhat谱范数界。若按论文通常使用的相同参考包络 `B_reference=ceil(B_verify)`，即使乐观取投影谱界1，仍得到 `beta=5260239171 >= q=4294967291`。这个**已配置参考包络**因此落入平凡SIS区，不能作为正式参数。此结论不声称一切更紧的参考包络都不可能；若另给有来源的、更紧包络，必须明确重审其条件。

显式提供 `measured['uniform_bounds']={reference_norm_bound: 整数, simulation_spectral_bound: 整数, source: 来源文本}` 时，审计才做相应β换算；它仍不认证调用者的来源。缺任一项则真实β保持null。无论换算是否落在非平凡区，安全标记均不提升，也不新增安全证明。

只读核验发现既有WSL `~/lattice-estimator` 可复用，HEAD为 `53da5982597709ba0fdf94ea37a84d822310fd84`；仓库内 `test-results/lattice-estimator` 未安装，不能直接假设PR67旧默认路径存在。该版本 `estimator/sis_lattice.py` 对norm2、β≥q明确拒绝；`red_shape_model` 对norm2被忽略，不能把lgsa名称当成该欧氏分支额外的有效形状模型。本批没有运行缺正确β的估计，也没有下载另一份estimator。

## 内存规划与实际验收分开

主档单个用户完整basis为18 GiB，主basis为8 GiB；紧凑主秘密约576 MiB、紧凑用户密钥约2112 MiB（均再加规范头与参数），签名精确393320 B。小编码不消除GPV准备阶段的稠密basis/QR内存。

审计采用五个用户方阵的规划余量（basis、QR工作、Q/R及额外复制余量）、两个大型trapdoor临时缓冲、主/用户紧凑状态、一次完整wire缓冲及native逐线程工作区，再留20%工作空间。当前主档规划约123.314 GiB，前提是单进程单实例、用户QR前释放主basis/star缓存、没有额外并发序列化或多份缓存。这个数字仅用于容量规划，不是malloc/LAPACK内存上界证明，也不是RSS实测。

`peak_rss_bytes` 未提供时，`target_memory_acceptance=false`；n2/n4的RSS不能冒充n512。必须真正运行n512完整实例并记录 `peak_RSS < 128 GiB` 才能验收目标内存；恰好128 GiB也不通过。若机器可用物理内存低于规划值，应先明确资源条件，不将估计当作已跑通。

## 有限采样诊断不冒充整链TV

native采用20σ窗口、192位dyadic概率质量和256位MPFR精度，模糊的区间决定明确失败。审计可算连续正态20σ尾概率参考、native窗口支持数上限对应的floor质量损失诊断，以及一次Setup+Extract+Sign的坐标调用量。这些仅为诊断量：连续尾概率不是任意移位离散高斯尾界；乘以坐标数也没有计入全部归一化、浮点QR/中心、根/用户接受门或中止分布。因此 `total_tv_bound=null`、`gs_bound_certified=false`、`abort_probability_bound=null`，不因此安排新的基础归约证明。
