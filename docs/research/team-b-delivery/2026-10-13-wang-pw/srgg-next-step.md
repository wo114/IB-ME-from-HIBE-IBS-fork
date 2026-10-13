# SRGG 相关扰动与提取组件

日期：2026-10-13。本页固定三个新文件的验收范围：`experiments/research/candidates/srgg/perturbation.py`、`perturbation_audit.py`、`tests/test_srgg_perturbation.py`。相关扰动与随机 gadget 已真实连接；本组件不实现完整 SRGG IBS、literal SampleF、连续高斯舍入或密钥卷积定理。完整四算法研究运行另行交付，不由本页自动升级状态。

## 原文与明确解释

来源为用户提供的 [Jia 等 2025 PDF](../../../../papers/2025_efficient_ibs_jia.pdf)，SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。PDF 第 6、7、8 页已渲染目视核对。

- Table 3、Algorithms 1/3 使用 `sigma=b*r`，因此本组件的主扰动形状为 `Sigma_p=Sigma-b^2*r^2*[R;I][R;I]^T`。PDF 第 5 页 §4.2.1 正文把相应位置写成 `r^2`；选择表格/算法解释并不等于已确认作者勘误。
- 完整系数空间形状用真实有限 GPV 采样，密度为 `exp(-pi*x^T*Sigma_p^-1*x)`，中心为零。物理协方差为 `Sigma_p/(2*pi)`；原表“标准差/协方差”措辞不能消去这个因子。
- 原 Algorithm 3 先抽下块，再用中心 `-sigma^2*R*p2/(sigma2^2-sigma^2)` 与 Schur 补抽上块；本组件直接抽完整相关形状，使用已有有理中心条件内核的有限误差证书。它是目标分布替代，不能称逐行执行 Algorithm 4。
- 原 Algorithm 4 明确包含连续 Gaussian 与固定 `r` 的随机整数舍入。图中输入是 `f,c`，平方根却写 `sqrt(d-r^2)`；`N_n` 的尺度也没有在该算法内定义。若采用普通 `N(0,I)`，连续扰动须乘 `sqrt((F-r^2*I)/(2*pi))`，才能对应原文密度。此处没有实现或隐藏这些步骤。
- Algorithm 6 字面写 digit 宽度 `r`，而第 6 页 `z=b*SampleZ(-v/b)+v` 和 Table 3 给出宽度 `b*r`。提取连接严格要求 gadget 平方宽度等于 `b^2*r^2`，不混用字面较窄分支。
- Algorithm 7 的 `u` 中心为 `-c/zeta=-c*zeta_star/2`。因为 `M_zeta*M_zeta^T=2I`，`zeta*u+c` 贡献 `2*r^2` 的形状；Table 3 的签名扰动却减去 `r^2*[y;1][y;1]^T`。该冲突保留，后续 factor 2 应标为“zeta 一致研究解释”，不能称原文已无歧义。

## 实现与隐私边界

`MasterPerturbation` 私有保存完整相关形状与主 witness，用 `OnlineNonSphericalSampler` 真实抽取有符号 module 向量。构造时执行完整移位正定条件、公共宽度类的 Loewner 检查、有理中心/有限路径/系数大小与熵带资源门；非法输入在消费随机数之前拒绝。抽样中止直接传播，无部分返回、重试或夹具回退。扰动和 gadget 随机源可分别注入；默认均为系统随机字节。

提取保留两个独立结果：原始向量满足 `A*y_raw=H-error (mod Q)`；随后 HNF 重建满足 `A*y=H (mod Q)`。后者改变首块，不能称为同一目标 Gaussian；两者均没有完整用户密钥分布/范数准入声明。公开审计分别记录两套方程次数，没有把组件误差加起来冒充卷积后的密钥误差。

秘密对象的 `repr` 隐去矩阵与向量。公开证书与审计逐字段白名单构造，禁止导出实际 witness、协方差、中心、gadget 辅助 trace 或用户向量。实际 `Sigma_p` 的交叉块为 `-sigma^2*R`，公开它可直接恢复主秘密，因此也不调用底层含私有几何的完整证书来生成报告。

## 小参数与实际验证

本组件固定审计 profile 为 `degree=2,rank=1,p=5,b=3,digits=1`，即 `q=3,Q=15`，主目标平方宽度为 `(512,128)`，`r^2=4`、`sigma^2=36`，系数维度为 6。公共条件宽度类 `[64,512]` 覆盖全部 81 个 CBD1 主 witness；测试逐个独立检查。一般输入必须重新通过相同门，不能沿用此覆盖结论。

TDD：首次运行新增测试得到 **21 failed**，全部正常断言组件或审计尚不存在；最小实现后 **21 passed in 4.27s**。相关回归最终 **112 passed in 3.98s**，exit 0：

```text
source ~/miniconda3/etc/profile.d/conda.sh
conda activate sage
PYTHONPATH=.pytest-tmp-sage-deps:src python -B -m pytest -p no:cacheprovider -q --basetemp .pytest-tmp-srgg-b tests/test_srgg_algebra.py tests/test_srgg_geometry.py tests/test_srgg_sampling.py tests/test_srgg_perturbation.py
```

检查涵盖实际交叉协方差诊断、81 个 witness、独立系数算子的两套提取方程、两随机源重放、输入前置拒绝、强制中止、公开报告白名单及资源/正定边界。随机统计只作诊断；Windows 无 Sage 时跳过不是通过。

最终公开白名单审计使用系统随机字节实跑 64 次：原始近似方程与 HNF 精确方程各 64 次通过、0 次失败，0 次中止，64 次首块改变。最终 `[64,512]` 类的公开最坏带长为 `2659488` 字节，扰动目标 TV 上界约 `4.783013e-24`；gadget fiber 上界约 `1.046212e-5`，二者未被误称为完整密钥分布界。运行命令为 `PYTHONPATH=src python -B -m experiments.research.candidates.srgg.perturbation_audit --repetitions 64`，exit 0。

此前纯内存 64 次系统随机探针中，两套 Sage 方程全部通过，63 次首块被 HNF 改变。该探针的公共标量类为 `[32,512]`，并非最终 `[64,512]` 类；不将两份资源数字混用。全部参数为教学研究配置，`security_claim: none`、`backend_admitted: false`，没有 ROM/QROM 安全、正式安全等级或生产适用性声明。

## 完整研究四算法的参数核算入口

后续拟用 `n=8,d=1,p=257,b=31,w=3`，有 `q=29791,Q=7656287`，主系数维度 40、签名维度 48。主目标平方宽度均为 `2^23`、`r^2=4`，CBD1 全支持的主扰动下界为 `6908668*I`；公共类 `[2^22,2^23]` 已在 Sage 实际构造，最坏公开带长 `17696000` 字节。

若完整重建用户向量范数平方门为 `2^29`、签名目标平方宽度均为 `2^37`，factor 2 的签名扰动下界为 `103079215096*I`；`gamma^2=48*2^37=6597069766656`，精确检查 `Q^2>4*gamma^2` 成立。`TableOptions(tail_bits=16,mass_bits=64,precision_bits=128,max_radius=128)` 与 digit 平方宽度 `3844` 实际构造成功，31 张表最大支持 8 点；gadget fiber TV 上界约 `0.0003360224765`，不能记为可忽略。

这些只解决该研究实例的尺寸、正定和一项模数门。小 `n`、8 bit 挑战、底层 EUF/sEUF 引用差异、完整卷积/重建分布、finite SampleF 精度和签名 factor 2 的来源解释仍必须分别记录；不因此宣称满足原文正式安全定理。
