# A2 第一批：ABB-ROM SampleR、BasisDel 与固定维度核验

日期2026-10-12，基点c026f9f。本批是**真实原语组件**，尚非完整 ABB HIBE 后端；A 目标保持进行中。旧教学 `abb10.py` 未改名或修改。原文为 [ABB10 CRYPTO 18页作者稿](../../../../papers/2010_lattice_basis_delegation_agrawal.pdf) PDF7/9/10/12；本批逐页核对并渲染检查BasisDel页。

## 已实现与原文对应

| 原文步骤 | 新代码行为 / 声明 |
|---|---|
| Definition7 / SampleR，PDF9 | m²个真正有限离散Gaussian标量组成整个整数矩阵；模q奇异则整批重抽，不逐列过滤。有限整次尝试/随机带、中止和矩阵条件化误差明确 |
| BasisDel step1，PDF10 | 精确计算 B=A·R^-1 modq、整数 S=R·T；R保留整数符号，不先约模 |
| Lemma1 completion，PDF10 | 用目标格的公开完整基作anchor，补全S子格，检查完整核格/行列式q^n及GS质量；不是只取S的HNF |
| RandBasis，PDF7/10 | 真正的零陪集GPV采样、独立整数列选择和完整基转换；规范化target格，不返回父基或补零trapdoor；失败不重跑 |
| 两层路径，PDF12 | F1=A·H1^-1，F2=A·H1^-1·H2^-1=A·(H2·H1)^-1；维度m不增长 |

公共入口 `ibme.hibe.abb_rom` 提供 SampleR、completion、FiniteBasisDel 与前缀矩阵；没有注册空HIBE适配器，不把这些对象计完整backend。依赖既有公共研究工具，同一数学provider复用，未改变旧Sampler/ToBasis guard。

## 有限分布与资源边界

SampleR比较的是“最多T次整矩阵”的理想过程，输出包含ABORT；实际-vs-理想TV取 `T*m²*δ_scalar`。理想每标量模q质量由周期Gaussian上界给出μ；连续列落入已有子空间的概率≤μ^codim，故完整秩概率≥∏(1−μ^k)。定向区间/向下量化得到公共下界，理想秩中止≤(1−p_lower)^T；不是借用未取得full version中的隐藏常数。

条件成功分布以独立理想Gaussian矩阵条件化于可逆为目标；在success下界非零时另外给 `2δ/(1−rank_abort−δ)` 上界。有限实现、随机源/中止明确；这不是矩阵RO indifferentiability或QROM证明。默认SecureRandom，固定byte RNG只用于测试。

当前原语沿用ToBasis192维、有限Gaussian平方宽度1..2^80、精确整数/算术/整次随机带限制。`parameter_gate.py` 单独报告原文 `m>6n log q` 的保守base2充分检查，不把维度检查升级为TrapGen/ω/LWE准入。n2/m84/q549755813911只用于原语输入；保守最小m为481，不能称论文完整选参。n2/q2^61−1/m733维度项能通过，但现有192维原语域不支持，其它论文条件仍未验。

## 问题、解决与实际84维证据

第一次84维输入由真实MP12计算型根给出完整核格；该输入**不是ABB TrapGen**。SampleR真实整批Gaussian、模可逆检查和完整格补全成功。GPV随后在随机化消费熵前因过度倾斜的基导致坐标宽度超出2^80被拒绝。原现场/pending保留；OS进程已终止，保存输入的无熵准入复核重现相同失败，没有因观察句柄丢失重启。

新增显式 `reduce_completion=True`：对完整格作确定性checked LLL，仍核对原文要求的**最大GS范数**不超过R·T；原ToBasis路径继续有逐坐标GS不增的强检查。规约可能增加某个坐标的GS，不能把最大范数条件错误写成每坐标条件；诊断分开记录。没有放宽Gaussian/ToBasis资源或重抽输入。

复用已保存的同一根/同一R，在新明确completion配置下执行：m84、q549755813911，R平方宽度27858240、委派平方宽度878484712634208000；采84次得到84个独立向量，输出完整目标核格，det=q²。约108.508秒，含读取/精确补全/规约/随机化；根与R新生成次数0。[公共收据](basis-del.json)不含私有基、原像、GS/标量诊断；只保存公共维度/宽度和方程结果。

16维公开代数fixture也完成真实两次逐级委派、根直接用H2·H1委派，目标矩阵相同、完整行列式相同、维度均16。两次随机基不比较字节相等；测试并不证明分布不可区分。

## 验收与未完成

- 新原语最终24项Sage测试通过，含子格指数2反例补全、非交换顺序、整矩阵失败/耗尽、真实Gaussian RNG、真实RandBasis、两级及直接乘积、私有84维输出独立验证、参数边界。
- 原有限采样/DelTrap相关回归33项；Windows88通过/2明确Sage skip。最终命令与版本范围见[audit.json](audit.json)和JUnit，开发重复不累加。
- 没有ABB一比特/字节加解密、公开HIBE六方法或CLI接入，没有ABB TrapGen，没有完整定理/有限ω参数和攻击成本；不增加已准入数，`security_claim=none, backend_admitted=false, parameters_are_formal=false`。

下一批应将原文TrapGen/两层宽度/真实SamplePre和位加解密接成第二个完整研究后端，同时解决目标维度工具范围；不能只再增加相同输入样本。首次Input的MP12根只验证BasisDel消费完整基的接口，不偷换论文Setup。

复验（源码根，使用指定WSL Sage）：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -p no:cacheprovider -q --tb=short \
  tests/test_abb_rom_primitives.py

PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python tests/install_probes/verify_abb_basis_del.py \
  --engine test-results/qfall-target/release/ibme-qfall-private-root \
  --private-directory test-results/abb-new-input/private --output test-results/abb-new-input/result.json
```

若首次准入在采样前失败，可在确认终止/保存输入后用 `--saved-input-directory <旧private>`、`--reduce-completion` 和新的私有/输出目录验明确新配置；不重抽原根/R，也不对已采样中止配置重试。private目录始终ignored。软件Sage10.9/Python3.13.14；CPU Intel Core Ultra9 275HX，身份/消息不适用（本批不是HIBE），每个实际委派一次；无性能排名/安全等级。

文件：`src/ibme/hibe/abb_rom/__init__.py`、`primitives.py`、`parameter_gate.py`，`tests/test_abb_rom_primitives.py`、`tests/install_probes/verify_abb_basis_del.py`、本目录公共材料与当前A2状态。源/论文SHA、真实失败与准确命令在审计中。提交信息 `feat(hibe): implement ABB SampleR and full-lattice basis delegation`；A未完成。
