# A3：结构化 MP12 SampleD、两次 DelTrap 与真实 2432 维诊断

本批按[成员 A 任务书](../../../workplans/2026-10-12/A-矩阵HIBE任务.md)继续 A3，承接[高维完整基筛查](../2026-10-14-scaled-parameters/README.md)。先固定复核 PR #15 `0435285`，四项远端检查通过，本地 Sage **330 passed / 21 明确历史实物或外部环境 skip**，三项真实 ABB 已保存实例契约全部执行，23 个冻结源码/工具 SHA 一致后，已合入远端 main，合并提交 `010b75e`。没有把研究合入升级为安全准入。复核 JUnit 和源检查见本目录 evidence；初次命令误写一个不存在的测试文件，收集零项，修正后收集351项，其中330通过、21跳过，不将零项或跳过算通过。

**本批新增实物：无需展开完整核格基的 MP12 Algorithm 3/4 研究工具。** 系统随机数下同一 n2 根完成两次真实 DelTrap、新原像和跨进程恢复；独立 n128 实例完成真实 Gaussian 根、2432维的4个新原像和跨进程恢复。这不是新的完整 HIBE，也没有32 B带噪声加密、Hybrid或IBME收据。既有 CHKP、MP12变体、ABB后端/默认参数/注册器和协议不变。

数学/实际执行源冻结 `5e4f332`；同组根角色筛查与新增边界测试为 `d0b0c20`。接口直接从 `ibme.lattice.matrix_sampling.mp12_structured` 导入，未占用共享 `__init__.py`/registry。唯一跨 A 边界的改动是当前进度文件：以本轮统筹审查/合入职责记录 PR15 及此工具，保持其它 owner 的版本事实。

## 1. 原文—实现—条件

来源为[MP12作者稿](../../../../papers/2011_lattice_trapdoors_micciancio.pdf) §5.2、§5.4/Algorithm3/Theorem5.5、§5.5/Algorithm4，固定PDF SHA在audit中。本轮提取并视觉核对PDF28的完整Algorithm3框和前提。没有用论文的 O(ε) 简写当成已给出整个实现的具体误差界。

| 环节 | 实物 | 边界 |
|---|---|---|
| 根 | 均匀 Â、真正有限离散 Gaussian R，Ā=[I\|Â]，A=[Ā\|G−ĀR]；根R整体范数门 | 计算型根，小Gaussian secret/error LWE逐列模型；没有统计近均匀结论，也没有native完整基转换 |
| gadget oracle | 每个二进制gadget只有k×k完整基：前k−1列2eᵢ−eᵢ₊₁、末列q的二进制digits，det=q、maxGS²≤5；同一块几何供n块GPV采样 | 实际采样，不能用digits分解替代Gaussian；6个素数含q61的完整格/GS独立测试通过 |
| 扰动 p | 目标 D_Z^m,√C，C=S²I−γ²TTᵀ，T=[R;I]；逐坐标球形Gaussian proposal及精确二次型拒绝 | 没有将C改成对角阵，没有连续正态RNG。有限截断/质量量化/中止分列；不自称MP12最优宽度 |
| SampleD | 新p、新gadget z，v=u−Ap modq，x=p+[R;I]z；逐次实际验证Ax=u | H=I、Σ_G=5I的显式子域；不实现其它tag或线上预处理队列，不缓存随机p/z |
| DelTrap | 对新尾块A₁的每列真实SampleD，目标G−A₁；得到R′后逐列范数、A_new[R′;I]=G及快照门 | 新块恰好nk列；当前CHKP/H/G块长度不能直接换用，本批不改变HIBE身份矩阵语义 |
| 状态 | 地址成功固定复用、失败/不确定占位、采样前callback保存opaque pending，严格键/状态恢复，公钥尾块/地址/范数绑定 | 新原语独立codec；不是旧HIBE wire，不含外部MAC/反回滚或CLI磁盘事务。克隆旧快照不能称全局只发一次 |

原文Algorithm3允许任意合格的扰动采样器。本实现替换的是离线采样方法，不是目标分布或在线原像方程。若b=1+公开R范数平方界、w=nk，取r²=4·smoothing_factor(w,128)，γ²=5r²，并固定

```text
S² >= max(7r²b, 10r²(w+公开R范数平方界)).
```

第一项满足原文Σ≥T(2+Σ_G)Tᵀ的保守谱门；第二项给出tr(γ²TTᵀ/S²)≤1/2。各特征值非负，乘积∏(1−λᵢ)≥1−Σλᵢ≥1/2；再结合球形normalizer上界，理想拒绝接受率至少1/4。宽度由**预声明公开范数界**选择，未用观察到较好的秘密R范数缩小宽度。

令d=S²−γ²、M=dI−γ²RRᵀ；对proposal p=(a,c)，y=Rᵀa+c，精确拒绝指数是

```text
Δ = γ²/(S²d) · [ ||y||² + γ²(Ry)ᵀ M⁻¹(Ry) ].
```

因此只存矩形R和m̄×m̄的Schur逆，不构造m×m的C/C逆或完整核格基。独立小维测试用完整C逆逐项核相等，并确认非零交叉项和det(C/S²I)≥1/2；完整基只在k维gadget块中使用。

## 2. 同组真实执行

两批各一次，分别新建根；没有把不同配置拼为同一链。默认系统CSPRNG通过计数包装注入，所有Gaussian、public uniform及Bernoulli均读该API；固定测试熵另列，不和系统批次相加。完整候选参数、阶段、实际字节、源码起止SHA、环境及限制在原始JSON。

| 批次 | 完整输入 / 已实际执行 | 时间 / 进程资源 / 状态 |
|---|---|---|
| 两层工具消费者 | n2、q257、R根平方宽16；m̄4、k9、w18，根/父/叶总维22→40→58；两层地址各86 B；根8次、两次委派各18列、叶8次，共52次新SampleD；同根状态及两个地址恢复 | 1.848639 s、1,246,273系统随机字节、峰值RSS228,028 KiB；新解释器重复取两层已发对象，熵调用0；[收据](evidence/two-level.json) |
| 超过旧完整基上限的工具诊断 | n128、q65537、R根平方宽529；m̄256、k17、w2176、总维2432；真实根R557,056项、17维共享gadget基、256维Schur逆；4个新SampleD及同根/全部原像方程恢复 | 108.624712 s、203,298,088系统随机字节、峰值RSS780,212 KiB；新解释器恢复熵0；[收据](evidence/n128.json) |

大批根生成64.914431 s、SampleD几何准备25.351862 s、4原像16.741665 s、跨进程恢复1.540606 s。计时不含父进程Sage启动，含所列步骤，二次重复/中位数不存在；资源为Linux进程ru_maxrss，不是全机器内存或最大工作区证明。硬件Core Ultra9 275HX，WSL Linux6.18.33.2、Sage10.9/Python3.13.14；OMP8/OpenBLAS1。

n128规范根快照实际1,676,774 B。全维完整基会有5,914,624个整数；本路径实际没有生成它。不同表示/不同算法路径的整数数量和wire不能替代同安全目标的完整IBME内存或性能比较，**不宣称端到端提速或压缩倍率**。

地址仅为这份原语状态的86 B标签；public extension是均匀模矩阵，不是已经实现的HIBE身份随机预言机。两个探针均无消息/seed加密。n128批次不做委派：当前A3工具下一层prefix上限512，而该根总维2432；不扩大该门或用独立根冒充Derive。

## 3. 错误预算、参数和安全负控

当前工具是独立显式执行域：n≤128、prefix≤512、total columns≤8192、R最多2²²项、密钥/状态32 MiB。原始后端的n64/完整基/GPV域没有改变。标量及gadget仍复用同一有限引擎，tail128/mass256/precision320，扰动最多512次，整call和整委派随机带均在采样前核预算；这些是累计可请求字节，不是预分配内存。n128一个SampleD的保守带上界759,423,598,592 B，实测消费见收据，不能混成RSS。

实际证书逐项保留：理想扰动拒绝中止(3/4)^512、finite proposal/weight coupling、n个gadget的有限耦合、全部proposal有理数路径门。**concrete_convolution_theorem_term、full_sample_TV_or_failure_upper、arithmetic_resource_abort_upper仍为null**。MP12原文O(ε)、硬件/分配、全部资源失败、拒绝范数事件与服务查询预算未给出一个闭合总界；有限权重项还依赖已注明的MPFR/MPFI有向取整界。没有将这些缺失项记为0。

同组[根角色筛查](../../../../experiments/research/matrix_structured_parameter_screen.py)不读任何key、R或原像，熵0；使用固定干净Estimator `53da598`。真实n128/q65537输入按一列n128样本、Gaussian squared width529进行比较，primal-uSVP log₂(rop) **21.608经典 / 19.610量子**，dual为25.413/23.098。这是理想Gaussian一列的启发式成本，有限PMF、全R范数条件化、全陷门/多目标和归约损失另计；不能称为实际完整私钥恢复。n2的primal两次AssertionError仍保存为error/null；8次调用共6有限、2错误。**n128并不因维度增加而获得128位安全，两个输入都不能作为比赛保密实例推荐。** 无密文角色，不填写/估计尚不存在的加密参数；[原始8次模型调用](evidence/input-screen.json)分列状态。

ROM未用于本工具的身份/矩阵生成；未来接入ROM HIBE的模型尚待。当前是教学/研究诊断参数，保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`，不新增HIBE/组合/困难假设计数。算法引用、等式及测试都不能替代安全证明。

## 4. 接口、测试、安装与重放

```python
from ibme.lattice.matrix_sampling.mp12_structured import (
    generate_structured_root, StructuredPreimageSampler, StructuredDelegator,
)
root = generate_structured_root(n, q, R_squared, rng=source)
sample = StructuredPreimageSampler(root).sample(canonical_syndrome, rng=source)
issuer = StructuredDelegator(root, persist_pending=save_opaque_state)
child = issuer.issue(address_bytes, public_n_by_nk_extension, rng=source)
opaque_state = issuer.to_bytes()  # PRIVATE: do not put in receipts or Git
```

Sampler不固定随机原像，调用总用新p/z；只有Delegator的已发R′固定。失败地址无法重发，换extension拒绝，恢复拒绝重复/追加/浮点/非规范字段、跨根及范数绑定错误；同址双线程只有一条流耗熵。生产随机数和显式固定测试随机源分别标记。

- 新结构化测试 **28 passed / 0 skip**（含实际输入无采样检查），定向Sage最终 **97 passed / 2历史源快照skip**；[JUnit](evidence/final-sage.xml)。此97含新28和既有矩阵/A0，计数不相加。
- Windows最终 **17 passed / 6 skip**；5项A0需Sage，结构化测试文件整体需Sage，skip不能当28项通过；[JUnit](evidence/windows.xml)。
- [仓库外安装收据](evidence/installed.json)：wheel SHA、`python -I`，六个provider仅来自安装包，复用同一系统生成的n2根，以**固定测试熵**运行新SampleD。未配置qFALL/Gram本地可执行文件，未从仓库源码回退；不等于默认HIBE/CLI接入。
- 首次新测试7个失败来自测试中的Sage矩阵迭代及漏导入ZZ，修正后原判据全保留；原始JUnit公开toy文本单列存证。后来的trace充分门取代初版逐维门，用预先声明的同一公开R界证明接受率，不因失败样本放宽门。

在WSL仓库根、指定环境下使用新目录，已有失败/未完成目录只观察或restore，不覆盖/重新生成：

```sh
export PYTHONPATH="$PWD/src:$PWD"
export OMP_NUM_THREADS=8 OPENBLAS_NUM_THREADS=1
~/miniconda3/envs/sage/bin/python -u -m experiments.research.matrix_structured_probe \
  --private-directory test-results/structured-two-level-new/private \
  --baseline-commit <固定提交> --n 2 --q 257 --root-squared 16 --samples 8 --delegate
~/miniconda3/envs/sage/bin/python -u -m experiments.research.matrix_structured_probe \
  --private-directory test-results/structured-n128-new/private \
  --baseline-commit <固定提交> --n 128 --q 65537 --root-squared 529 --samples 4
~/miniconda3/envs/sage/bin/python -m experiments.research.matrix_structured_probe \
  --private-directory <已完成的原目录> --restore-only
~/miniconda3/envs/sage/bin/python -m pytest -p no:cacheprovider -q \
  tests/test_mp12_structured_sampling.py tests/test_matrix_finite_sampling.py \
  tests/test_chkp_matrix_profiles.py tests/test_matrix_hibe_scaled_screen.py
```

代码、准确命令/结果、source/paper/evidence SHA、安装及PR15审查记录见[audit.json](audit.json)，精确文件列表见[files-changed.txt](files-changed.txt)。私钥、R、原像、随机带/种子、opaque状态和native私有诊断都只在ignored测试目录，没有进发布材料。

本批完成A3真实消费者和新执行边界，不宣称A全部完成。后续WIP为：正式尺寸与谱/宽度条件、具体卷积/总体失败预算；适配真正HIBE的扩展块与H/G固定叶、严格公开后端/容量/wire、32 B诚实噪声/完整组合、安装CLI及攻击验收。新工具输入/参数改变时须重新核这条链，不把子环节或原像成功当完整IBME进步的量化性能结论。
