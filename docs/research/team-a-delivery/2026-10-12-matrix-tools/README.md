# A3：统一矩阵有限采样、完整基与 ABB 消费者

开始日期2026-10-12，真实实验于2026-10-13完成，基点 `f6090c9`。本批补公共矩阵工具与实际消费者，A2完整HIBE仍WIP。不是新增密码算法或安全实例；旧教学后端、CHKP/MP12两个命名及none/false声明保持。

## 代码、认领与复用边界

数学唯一实现迁入 `ibme.lattice.matrix_sampling`：`scalar.py`、`gpv.py`、`basis.py`、`randbasis.py`；公开namespace按需加载Sage，普通import不初始化Sage或消耗熵。认领的旧 `first_suite/finite_gaussian.py`、`finite_gpv.py`、`finite_randbasis.py`及 `chkp_tobasis.py`只留下兼容入口，保留旧方法/配置/逐字节行为及硬上限。没有复制一份新的Gaussian或RandBasis，也没有修改队友PR #14的 `src/ibme/lattice/chkp/`、协议、registry、CLI或B/C文件。

`ibme.hibe.abb_rom`新增显式 `MatrixSampleR`、`MatrixBasisDel`、`prepare_matrix_basis_del`消费者：整矩阵IID Gaussian、模q奇异才整批换矩阵，真正变换/完整格补全/独立零陪集随机化；旧 `FiniteSampleR/FiniteBasisDel`仍走其旧profile。来源仍为ABB10 SampleR/BasisDel、GPV08 SampleD、CHKP RandBasis及前批核对的完整格补全材料。本批公开入口不是空适配器，不计作完整HIBE。

| 内容 | 旧profile | 显式Matrix profile |
|---|---|---|
| Scalar平方宽度 / 支持端点cap | 2^80 / 2^48 | 2^192 / 2^112；端点表示，不枚举支持 |
| Options rational bits / 最坏tape cap | 8192 / 1TiB | 65536 / 16TiB；预算是累计随机字节上界，不是分配该内存 |
| GPV维度 / 输入整数bits | 256 / 1024 | 1536 / 4096；完整基/GS/全部中心与路径先核再抽熵 |
| 完整基维度 / 整数entry bits | 192 / 8192 | 1536 / 65536；规范完整格，不能只取变换子格HNF |
| SampleR模数 | 奇素数≤2^61−1 | 奇素数<2^256；整矩阵尝试数/条件化误差另外计算 |
| 模型与安全 | none/false | none/false；宽度或执行域不能变成安全等级 |

默认有限options仍tail128/mass256/precision320/abort128/uniform192。每个新输入重新计算尾、Poisson质量、量化、拒绝中止、C1及整次tape，没有沿用空证书。Matrix GPV另外检查输入/已存精确几何的整数有理数内容预算，默认1GiB；它是数学数据表示的字节预算，**不是Sage/Python进程RSS保证**。

## 三个保持原始数学语义的实现步骤

1. Wide ToBasis只请求坐标矩阵Z的行HNF R，再求整数 U=Z·R^-1、T=B·U；和旧R=V·Z、U=V^-1输出相同。严格检查整数、T·R=S、R上三角/非零整数对角及完整核格det=q^n。由该精确分解得到逐坐标GS不增，避免再次形成极度偏斜的大有理GSO；不宣称谱范数或普通列范数界。旧入口仍保留原兼容路径。
2. RandBasis用辅助素数秩作**充分的独立性提示**；模p相关时必须回到整数秩判定，若整数独立则接受并关闭提示。不能把模p相关当拒绝。测试包含65521倍向量反例、倒序pivot及旧输出差分，没有改变候选接收、熵或目标分布。
3. Matrix专属固定LLL使用预定delta=.75/eta=.501，随后精确size reduction、完整格/整数变换、GS上界和Lovasz .74检查。它没有降低Gaussian、公开GS或范数门。BasisDel完成阶段验证输出最大GS不超过R·T第一列范数平方；第一列就是原第一条GS，故这足以证明原文最大GS质量义务。无法据此证明逐坐标关系时记null，不能填true。旧 `.999/.99` helper未修改。

LLL是明确的实现后处理，不能直接借用“原稿完全相同输出”或新增算法计数。矩阵RO、Theorem3有限常数/分布和完整HIBE仍需逐项对应。新全矩阵整数空间不截断q或带符号私有系数。

HNF工作量预检是**声明的预测模型**，不是库内部workspace/RSS的证明上界；之后另检查实际返回整数矩阵内容。它可能拒绝实际可跑的输入，passing也不能保证库分配不会失败。RandBasis的rank/norm/DGS界与这种workspace失败分开：包含workspace的总失败界为null；实际-vs-指定有界理想过程TV仍包含相同确定性后处理/中止规则。不得把理想rank/norm界当完整运行可用性。

## 实测、旧差分和安装

最终Sage **168 passed / 3 skipped**，本批28项新测试；Windows **116 passed / 5 Sage依赖skip**。两批重叠不求和。Sage缺两个旧native私有witness及一个旧84维witness，不当pass。[准确命令/来源](audit.json)、[Sage](sage.junit.xml)、[Windows](windows.junit.xml)。没有运行ABB完整组合，也没有改参数保住旧测试。

实际验证：2^96/160/192平方宽度各512个离散Gaussian样本的均值/方差/尾和范围；系统bytes调用；257维真实GPV陪集；193维完整基；巨大宽度真实RandBasis；16维公开代数输入的两次实际BasisDel及最终矩阵/完整行列式。小夹具明确公开，不冒充真实AP09根或HIBE实例。

从固定 `f6090c9`保存四个旧provider源码，在新进程实际比较旧/新scalar证书与随机字节输出、GPV、RandBasis完整基/使用次数、ToBasis，并另比dense三角求解与旧完成输出。这些是固定测试熵，证明回归兼容，不证明密码安全或两个理想分布相等。

最终wheel[安装记录](installation.json)：仓库外 `/tmp`、Sage `-I`仅追加隔离安装目录，24个已加载provider全部来自安装包；系统宽scalar、真实宽GPV陪集、固定规约均通过，源码路径导入0。Windows普通lazy namespace import不需要Sage。wheel/源散列在审计，安装测试不等于完整CLI验收。

本机Intel Core Ultra9 275HX、WSL可见约15.35GiB、Sage10.9/Python3.13.14；固定测试和真实CSPRNG实验分开，未做公平性能排名。新工具的采样误差、资源中止与安全/归约分别核验，统计测试不能代替安全证明。

## 248维真实输入：保留中断并继续核验

沿用前批真实AP09 `n1/q549755813911/m248` 根，**新根0**。先完成1个整矩阵系统Gaussian R，8.002秒、25510153随机字节；同组sigma1/sigma2/tau按前批公开充分链取值，不按实测秘密几何挑参数。

第一次在父BasisDel确定性准备的 `.999` LLL停留较久，native栈实际定位为fplll LLL。确认父RandBasis尚未进入、输入已保存后，显式SIGINT结束PID306；退出1且进程已不存在。[中断收据](interrupted-preparation.json)保留root/R/阶段/源指纹；原目录pending保留。没有父通过收据，不把此中断称为Gaussian分布或论文数学失败。原总耗时未捕获，记null。

随后选择声明的Matrix固定 `.75` normalizer，在**新目录**从同一份根/同一份R继续；入口要求原终止及零父采样事实，不重新生成根/R、不解除旧pending。历史[观察](running-observation.json)只保存当时过程，不冒充完成。2026-10-13原进程退出0，[最终九阶段收据](delegation-complete.json)逐项passed并核对所有provider源SHA：新根/首R生成均0；实际第二R、两次RandBasis及最后叶陪集SamplePre完成，原u0方程通过。

| 同一实物阶段 | 秒 | 实际随机字节 |
|---|---:|---:|
| 首R复用 | 0.009 | 0 |
| 父BasisDel准备 | 1386.312 | 0 |
| 父RandBasis | 140.362 | 28853755 |
| 父固定规约 | 6668.083 | 0 |
| 第二R | 7.715 | 25570229 |
| 叶BasisDel准备 | 1994.297 | 0 |
| 叶RandBasis | 152.430 | 36360244 |
| 叶固定规约 | 26411.883 | 0 |
| 新叶SamplePre | 285.011 | 156662 |

总计37046.205秒（约10.29小时）、90940890随机字节；进程峰值RSS1184036 KiB。根/父/叶维度均248，真实完备格和目标方程通过。耗时主要在确定性规约，不能把该单次总过程写成纯采样微测、完整IBME性能或相对旧中断过程的加速比；共享开发机并非隔离公平测试。最终源码对应该实际进程，未重新生成实物补收据。

两次矩阵变换暂未实现身份H oracle，也未做五类codec、固定身份状态、256位叶载荷或Luo/Hybrid组合。本配置的同组两层噪声充分界仍失败，n1困难性负控仍成立；原语方程成功不会放行这个配置作完整安全HIBE。

可重放入口（必须新私有目录，统一WSL `~/miniconda3/envs/sage`；提交SHA在宿主取得）：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.abb_rom.delegation_probe \
  --saved-private-directory test-results/abb-ap09-root-bits/private \
  --private-directory test-results/abb-delegation-new/private \
  --output test-results/abb-delegation-new/receipt.json --baseline-commit <宿主40位SHA>
```

只有保存了明确终止/零父采样历史的诊断输入才可另加 `--resume-input-directory <原private>`继续新配置；采样已经失败的地址不由此重试。私钥、实际R/基/原像、raw native栈/几何缓存/RNG与运行状态都在ignored目录，Git只提交脱敏记录。

本批文件：上述五个公共模块；四个认领兼容入口；ABB `__init__.py/primitives.py`；专属测试 `tests/test_matrix_finite_sampling.py`；`experiments/research/abb_rom/delegation_probe.py`；本目录README/audit/JUnit/安装/中断及未完成观察；仅A3对应的任务/进度说明。兼容文件迁移和A3进度改动是为单一数学来源与真实消费者，不修改团队公共协议语义。

WIP：248维原语委派路径已经实跑，完整ABB接口/对象/组合、目标高n参数与模型、AR储备仍缺。`security_claim=none / backend_admitted=false / parameters_are_formal=false`。
