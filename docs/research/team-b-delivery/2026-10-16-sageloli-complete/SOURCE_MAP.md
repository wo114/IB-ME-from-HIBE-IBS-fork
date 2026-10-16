# Sageloli SIS／RSIS v2：来源—算法—实现映射

选定版本为 [HAL v1](https://hal.science/hal-04107694v1)，DOI `10.1007/978-3-031-33488-7_24`。本地冻结文件 [`2023_shorter_faster_ibs_sageloli.pdf`](../../../../papers/2023_shorter_faster_ibs_sageloli.pdf)，SHA-256 `0e92f184828bc8643a774e9c334b14689346387981e766c311c596239ef73e3e`。PDF 共73页，下表同时给出印刷页与 PDF 页，避免将出版社短稿页码混入。

## 主算法对应

| 来源（印刷页／PDF页） | 原文对象或条件 | v2 实现 | 对应边界 |
|---|---|---|---|
| p7／8，模运算约定 | 模元素范数使用中心代表元 | `algebra.centered`；`backend._split_ok` | 公开签名居中；私有Gaussian lift保留整数 |
| p8／9，概率与Gaussian定义 | `P_1/2`、`P_(R,1/2)`；`rho_s(x)=exp(−pi*||x||²/s²)` | `backend.setup`；`config` density-width-squared | 不把 s 误作物理标准差 |
| p12／13，Prop.2 | `A=[Abar|G−Abar*R]`，CBD根 | SIS Setup／`algebra.matrix_public` | Abar使用有限预算无偏均匀采样；根负号见下文 |
| p12／13，Prop.3 | SampleD 输出完整晶格陪集Gaussian；DelTrap对 `H−G` 每列调用 | `sampling.prepare/draw/delegate_matrix` | 真全维扰动；数值总TV尚未认证 |
| p13／14，Prop.5 | 同根多个身份、同身份多次签名的Gaussian分布条件 | 保留raw身份陷门；签名raw J的PSD准入 | 不把该命题误用为固定服务的完整自适应归约 |
| p17／18，Fig.5 | 自适应SIS：KeyExt盐r，Sign盐s，非齐次方程 | `SISBackend`、`hashing.sis_h1/sis_h2` | 五方法另含严格解析；无第二次消息陷门委派 |
| p18／19，Table2 | SIS宽度、分块签名范数 | `config.SISParams`；`width_check` | 默认小参数只检查充分宽度式，非正式参数 |
| p22／23，Fig.7／Table4 | 自适应RSIS，`R=Z[X]/(X^d+1)`，两块范数 | `RSISBackend`、环运算与展开检查 | d至少4且为2幂；默认d4,k9,l22满足结构条件 |
| p51／52，Prop.18 | 环根分布前末四分之一为4CBD1，中间二分之一为CBD1 | `RSISBackend.setup` | 不以普通全系数CBD1替代 |
| p52／53，Prop.19 | 从矩阵SampleD提升SampleDR；DelTrapR做k个环列 | `sampling.delegate_ring`；negacyclic展开 | 抽k个系数向量再旋转，不独立抽dk列 |
| p53–54／54–55，Prop.21 | raw身份钥的谱范数与后续宽度条件 | 实际raw J的精确PSD检查；raw尾界失败门 | 工程尾界不是该命题完整概率／安全证明 |
| p9–10／10–11，IBS游戏、Fig.1 | OSign每次重新KeyExt／新r | `FixedIssuer`固定缓存r与用户钥 | 明确服务差异；ROM／QROM对应仍待核 |
| p27／28，§8.1、Table6–7 | 两组d2048大RSIS点、作者估计尺寸与安全 | 文档记录，未运行 | 不把作者估计移植为当前实现/NIST准入；无SIS发表点可复现 |

## 明确的解释与工程增量

1. **根负号。** p12 Prop.2 的 `G−Abar*T_A` 与同页 `A[-T_A;I]=G` 定义按字面相冲突。实现存储 R，构造 `G−Abar*R`，根 sampler 用 `T=−R`；委派输出 `T_id` 满足 `A*T_id=H−G`，签名 sampler 用正的 `T_id`。所有实际关系均精确核验。
2. **环展开方向。** 原文 Rot 描述含行／列记法歧义。实现采用第 j 列为 `Cf(X^j*a)` 的列作用矩阵，显式检查乘法一致及 `X^d=−1`；这与协议所需线性关系一致。
3. **SampleDR维度。** Prop.19 写 SampleDR 输出 `R_q^k`，而其输入 A 有 l 列、Fig.7也要求 l 维输出。实现按实际方程输出 l 个环多项式。记录解释，不宣称原文已正式更正。
4. **Gaussian内部核。** Sageloli没有独立SampleP伪代码。这里复用先前探针的全局SampleF／分块Schur核：`Pi=s²I−9r²JJ^T`，在取熵前检查 `s²I−11r²JJ^T` PSD；先采全维p，再采全部k个ternary陪集digit，最终 `z=p+Jx`。最后carry可非零。数值连续阶段、精度与整体TV未认证，不继承论文抽象gamma。
5. **私有raw范数。** 身份钥保留Gaussian整数lift；raw尾界失败后标记failed，不重新发钥。公开签名根据p7按模q中心代表元检查两块范数。失败门和资源上限是工程增量，不称为原文KeyExt中的显式步骤。
6. **哈希／编码／持久化。** 域分隔SHAKE、规范长度前缀、v2对象、无偏拒绝取模、固定缓存、并发锁及崩溃pending是本仓库工程封装。理想随机预言机、实际SHAKE和本地状态真实性是不同问题。
7. **有限预算。** 取模每值192候选／总64MiB字节，锁等待300秒，状态与对象16MiB。预算耗尽明确中止；只有锁获取可等待重试，已进入的事务不自动重跑。Gaussian数值计划不写入对象或收据。

## 参数与当前声明

| 分类 | SIS | RSIS |
|---|---|---|
| 本次可执行教学点 | n2,k4,m16,q81；s_id²=2^28，s_sign²=2^56 | d4,k9,l22,q19683；s_id²=2^36，s_sign²=2^66 |
| 宽度核验 | Table2；r²16，epsilon2^-64，C38 | Table4；r²16，epsilon2^-64，C38 |
| 原文发表大点 | 未给出对应具体SIS点 | Table6：(65,2048,132)、(153,2048,308)，epsilon2^-200；未运行 |
| 参数安全 | 无：范数界在小模数下空泛，公开线性伪造可行 | 同左 |
| 实现目标 | 完整独立研究生命周期 | 完整独立研究生命周期 |
| 安全准入 | `none / false / false` | `none / false / false` |

论文部分平滑／完整性表达式含 `−d(2k−l)` 指数，同时约束 l>2k，按字面相关项增长；本批不静默改号并继承结论。标准化对标、正式困难性估计、有限误差／查询预算、固定服务的安全游戏映射仍属于单独核验；本次不重新证明基础定理，也不以有限攻击未成功充当安全证明。

## 本批验证记录待填

- 代码提交：`集成提交由本次交付的最终 Git 提交记录；未单独创建或修改其它分支。`。
- 独立生命周期／攻击收据：``build/outputs/sageloli-complete-2026-10-16/sageloli-all.xml`（不含私钥、签名样本、随机带或私有采样计划）`。
- 测试命令、结果、实际环境、计时及重复次数：``PYTHONPATH=src:. PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_sageloli_ibs.py tests/test_sageloli_sampling.py tests/test_sageloli_uniform.py tests/test_sageloli_service_recovery.py tests/test_sageloli_probe.py` → **144 passed, 0 failed, 0 skipped in 222.80 s** (WSL Ubuntu-24.04, Sage 10.9, Python 3.13.15). JUnit: `build/outputs/sageloli-complete-2026-10-16/sageloli-all.xml`; service recovery subset: 36 passed in 79.06 s; uniform subset: 53 passed in 0.53 s.`。
- 未在本映射中印出主陷门、身份钥、签名样本、种子、随机带或私有采样计划。
