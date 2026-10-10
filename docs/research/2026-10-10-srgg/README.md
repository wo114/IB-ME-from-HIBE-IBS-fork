# SRGG 基础：公开关系、HNF重建和协方差形状

日期：2026-10-10；基点 `71a1470`，上一轮GitHub CI run37970155844已成功，远端无新增提交或PR。本轮在独立候选目录实现SRGG的代数与几何基础，不修改队友CHKP、已有HIBE/IBS、协议、哈希输入或正式接口；没有性能优化。

后续进度：第二轮[随机gadget参考](../2026-10-10-srgg-sampling/README.md)已接真实有限误差高斯内核，明确SampleZ仿射宽度及陪集归一化偏差；本页记录第一轮的历史范围，完整扰动/签验仍未完成。

**已交付可运行的模环公开关系、带误差原像的密钥重建、签名承诺恢复，以及精确有理协方差正定/Schur检查。** 新增51项检查跨Windows/指定WSL Sage通过；独立Sage核验36个二进制挑战、72个恢复值修改对照和9组协方差形状。完整结果见 [audit.json](audit.json)，代码在 [候选目录](../../../experiments/research/candidates/srgg/algebra.py)。

这些是数学基础单元，**没有实现高斯采样、XOF、身份/挑战哈希、完整Sign/Verify或IBSBackend**；全部 `security_claim: none`、`backend_admitted: false`，不计新增完整算法或组合实例。

## 1. 原文定位与本轮解释

来源是用户提供的 [Jia等2025完整稿](../../../papers/2025_efficient_ibs_jia.pdf)，12页，SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。已实际渲染并完整检查PDF5/7/8页算法图，结合PDF6页Table3，避免文本提取丢失横线、平方和上下标。

| 来源位置 | 实现 |
|---|---|
| §4.1 / Algorithm1，PDF7 | `build_public`，$B=F-[I_d|\hat A]R\pmod Q$，$A[R;I]=F$ |
| §4.2 / Algorithms2、5、6，PDF7 | `gadget_digits`仅提供规范余数的确定性方程夹具；`extraction_from_values`计算$Ay=H-e$ |
| Algorithm7行1–2，PDF8 | `reconstruct_vector`从保留尾块恢复首块，取得精确$Ay=H\pmod Q$ |
| Table3 / Algorithms7–8，PDF6/8 | `signing_matrix`、`response_from_values`、`recover_commitment`；恢复承诺但不做挑战哈希或范数验收 |
| Table3 / Algorithm3，PDF6/7 | `master_geometry`；主扰动形状、条件中心及Schur补 |
| Table3签名扰动，PDF6 | `signature_geometry`；原文系数与乘以ζ的另一形状尺度分别检查，不自动批准采样解释 |

研究采用Algorithm3和Table3一致的$\sigma=br$及$\Sigma_p=\Sigma-\sigma^2[R;I][R^T|I]$。PDF5页§4.2.1正文把相应位置写为$r^2$，与算法图不同。本轮按算法/表格实施并保留差异；这是主AI在独立基础单元中的明确解释，不是修改生产协议或补写原文安全证明。

## 2. 可执行的环代数

环为$\mathbb Z[X]/(X^n+1)$，$n$为2的幂；所有整数负循环乘法精确执行，公开系数规范在模数范围内，私有向量保留符号。主矩阵有$(2+w)d$个环列，$R$为$2d\times wd$，$F=I_d\otimes p(1,b,\ldots,b^{w-1})$。研究配置令$q=b^w$、$Q=pq$。

给定残差系数v，本轮确定性夹具取$e=v\bmod p$，分解$(v-e)/p$为w个b进制数字。于是$Fx=v-e\pmod Q$。它与Algorithm6所需Gaussian输出的分布不同，**不作为ApproxGadget采样器**。输入扰动也由调用者给定，不是假装Gaussian的均匀掩码。

由$A[R;I]=F$，计算$y_{\rm raw}=p_{\rm perturb}+[R;I]x$得到

$$Ay_{\rm raw}=H-e\pmod Q.$$

保留尾向量$y'$，按Algorithm7从HNF首块重建

$$y_0=H-[\hat A|B]y'\pmod Q,\qquad y=(y_0,y').$$

代码将重建首块的模系数选为中心化整数代表元，尾块不变；精确核对$Ay=H$。这一步修正的是方程，尚未认证重建后私钥的目标分布/范数。

令$\zeta=1+X^{n/2}$、$j=(\zeta^*,0,\ldots,0)$及$b_{\rm id}=Qj-2H$，则

$$\bar A=[2A|b_{\rm id}],\qquad\bar A[y;1]=Qj\pmod{2Q}.$$

对给定的整数u、二进制多项式c和扰动向量p，参考计算

$$z=p+[y;1](\zeta u+c).$$

由于$\zeta\zeta^*=2$，恢复$\bar Az-Qjc$恰为$\bar Ap\pmod{2Q}$。Algorithm8第3行及正文有些位置省略A的横线；代码依据已经声明的列数和上述关系使用完整$\bar A$，避免把旧A与多一列的z相乘。恢复式经过独立商环计算核对。

负面对照保留：没有范数/分布要求时，任何人可以在HNF首块填入公开H并满足签名关系。因此“方程成立”不是持有合法签名密钥或完整认证通过；本轮没有把这些夹具记作真正签名。

## 3. 协方差形状与条件中心

[geometry.py](../../../experiments/research/candidates/srgg/geometry.py)将每个环元素映射为负循环系数算子，环矩阵转为有理系数矩阵。转置采用算子转置，即环上的共轭转置；仅交换模块索引而不共轭是错误的，测试保留这一对照。所有形状、LDL枢轴和Schur补均用精确Fraction运算，不用浮点“接近正定”判定。

主扰动的下块$D=(\sigma_2^2-\sigma^2)I$，条件中心算子为$-\sigma^2 R/(\sigma_2^2-\sigma^2)$，条件上块为

$$\Sigma_2=\sigma_1^2I-\frac{\sigma_2^2\sigma^2}{\sigma_2^2-\sigma^2}RR^T.$$

入选条件是$\Sigma_p\succ r^2I$。代码同时检查完整移位矩阵以及其移位Schur补；不仅检查$\Sigma_p\succ0$，也不将“未移位Schur补减去$r^2I$”错当完整移位条件。PSD边界、负枢轴、非对称矩阵、尺寸、精确输入与资源超限均拒绝。

返回的是几何条件和中心，不是离散Gaussian采样或其误差证书。Gaussian形状参数也不与物理方差中的$2\pi$约定混用；后续实现须独立对应密度、标准差和原文记号。

### 采样宽度仍需核对

1. Algorithm6写$D_{b\mathbb Z+v,r}$，而PDF6页建议$z=b\cdot\mathrm{SampleZ}(-v/b)+v$，前文SampleZ固定宽度r。按密度定义，后一配方的形状尺度是$b^2r^2$，宽度为br。两处宽度记号不能未经核对混接；本轮没有生成任一Gaussian输出。
2. 签名中$u\sim D_{R,r,-c/\zeta}$后乘以ζ，系数算子满足$M_\zeta M_\zeta^T=2I$。Table3字面签名扰动却减去$r^2[y;1][y^T|1]$。参考分别检查噪声系数$r^2$与$2r^2$的几何配置；两者都通过一个宽配置，不表示这一采样/卷积解释已解决。
3. 原有Theorem2底层sEUF-CMA前提以及q/Q/γ适配仍待核验，本轮不从正定或代数成功推断QROM不可伪造。

这些是实现前应明确的条件与版本差异，不是宣称攻击成功或直接淘汰SRGG。

## 4. 实际参数与检查

参数为手选教学配置，不复制作者安全位数：

| n / d / w / p / b | Q | 主几何维度 | 签名几何维度 | 全二进制挑战 |
|---|---:|---:|---:|---:|
| 2 / 1 / 1 / 5 / 3 | 15 | 6 | 8 | 4 |
| 4 / 1 / 2 / 5 / 3 | 45 | 16 | 20 | 16 |
| 4 / 2 / 2 / 7 / 3 | 63 | 32 | 36 | 16 |

三份主扰动使用$(\sigma_1^2,\sigma_2^2,r^2)=(4096,64,1)$，签名形状使用$(\bar\sigma_1^2,\bar\sigma_2^2,r^2)=(2^{20},2^{18},1)$。小矩阵R的测试流按CBD1产生系数；公开矩阵/目标值和调用者给定的扰动只用于代数实例，没有实际XOF、身份、消息或挑战哈希。每个挑战运行1次，所有36个输入均保留；72个改挑战/改响应恢复值对照均被检测。三个病例均出现非零近似余数，并成功重建精确关系。

Sage独立用整数多项式商环计算公开关系和响应，用QQ矩阵重新建立系数算子、形状、完整正定性、条件中心及两个Schur补，不只是调用参考自己的检查函数。9组形状全部通过。结果不输出主/用户向量、种子或完整私有形状。

研究资源限制：$n\le8$、$d\le2$、$w\le4$、$p\le257$、奇数底数$3\le b\le31$；单系数最多128bit，系数算子维度最多128，有理数及中间LDL值最多8192bit。作者$n=512$的完整配置没有在这里运行，超限不会截断或悄悄换参。

## 5. 测试、交接和下一项

Windows Python3.14.6 / pytest9.1.1和指定WSL Sage10.9 / Python3.13.14均51 passed，无XFAIL；候选目录/Yu/SRGG合并回归Windows122 passed，Sage另含13项公共预检查，共135 passed；Intel Core Ultra9 275HX。没有高斯统计、格攻击成本或密码性能结果。本轮所有最终检查通过；初次读取Poppler位置失败后改用已安装的原生程序完成视觉核对，没有改论文文件。

```text
python -B -m pytest -p no:cacheprovider -q tests/test_srgg_algebra.py tests/test_srgg_geometry.py
wsl -- bash -lc "cd /mnt/d/zcode_projects/ibme && ~/miniconda3/envs/sage/bin/python -B -m pytest -p no:cacheprovider -q tests/test_srgg_algebra.py tests/test_srgg_geometry.py"
wsl -- bash -lc "cd /mnt/d/zcode_projects/ibme && PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -B -m experiments.research.candidates.srgg.audit --output test-results/srgg-audit.json"
python -B -m pytest -p no:cacheprovider -q tests/test_candidate_foundations.py tests/test_yu_homomorphic_reference.py tests/test_srgg_algebra.py tests/test_srgg_geometry.py
wsl -- bash -lc "cd /mnt/d/zcode_projects/ibme && ~/miniconda3/envs/sage/bin/python -B -m pytest -p no:cacheprovider -q tests/test_candidate_foundations.py tests/test_candidate_preflight.py tests/test_yu_homomorphic_reference.py tests/test_srgg_algebra.py tests/test_srgg_geometry.py"
```

修改文件共15个：

| 范围 | 文件 |
|---|---|
| 参考代码 | `experiments/research/candidates/srgg/algebra.py`、`experiments/research/candidates/srgg/geometry.py`、`experiments/research/candidates/srgg/audit.py` |
| 单元检查 | `tests/test_srgg_algebra.py`、`tests/test_srgg_geometry.py` |
| 本轮报告/公开结果 | `docs/research/2026-10-10-srgg/README.md`、`docs/research/2026-10-10-srgg/audit.json` |
| 候选交接 | `experiments/research/candidate_catalog.py`、`docs/research/2026-10-10-foundations/catalog.json`、`docs/research/2026-10-10-foundations/候选基础卡与队友接手任务.md` |
| 规格/工作记录 | `docs/research/2026-10-08-r1/SRGG2025IBS实施规格与条件.md`、`README.md`、`docs/PROJECT_RESTART.md`、`docs/workplans/2026-10-08/主AI任务-IBS集成与优化.md` |
| CI | `.github/workflows/basic-checks.yml` |

候选生成器仅修正后续实验的报告指向，避免把新实验写成已在旧preflight.json中执行。跨代码/研究文档的原因是给队友可运行基础及明确接入条件；没有访问其它模块私有矩阵或修改算法接口。

下一项：在宽度约定明确后，复用已有真正标量/相关Gaussian参考工具建立一个有限扰动/gadget采样用例，分别核对模误差、分布和中止；然后再接规范哈希、固定身份缓存及四算法。原文已有定理继续引用，不默认重做基础QROM证明。CHKP首套交接一旦到达仍优先集成；三个代表依照完整实例比较选择，优化继续后置。

WIP：真正采样、宽度映射、XOF/哈希、Sign/Verify与原语/完整IBME未实现；旧education两个认证反例未关闭。全部none/false，测试不替代安全证明。
