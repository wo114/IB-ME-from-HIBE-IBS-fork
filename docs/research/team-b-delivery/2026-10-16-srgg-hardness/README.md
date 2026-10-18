# SRGG：独立困难性筛查与有限参数搜索

2026-10-16。本项独立于 HIBE，固定 CBD1 根分布、现有充分几何条件和直接 classical-ROM 归约，进行零熵参数筛查。**当前 n512/d2 研究点的通用格攻击成本对照很低，不能支持 Kyber/ML-KEM 对标目标。** 有限搜索得到可继续核验的较大研究点，尚未得到正式安全参数，也未执行恢复陷门或伪造签名的攻击。

`security_claim=none, backend_admitted=false, parameters_are_formal=false, nist_security_category=null`。本项没有改旧默认值、公共后端或冻结证书。所有成本均为所选工具和模型的启发式输出，不能作为攻击下界、成功概率上界或安全证明。

## 1. 对应对象与可复现工具

来源方案为 *Constructing Efficient Identity-Based Signatures on Lattices*，DOI [10.1049/ise2/6684889](https://doi.org/10.1049/ise2/6684889)，已冻结 PDF SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。本项使用仓库已经明确的密度形状约定、ζ 因子修正和 [direct-ibs.md](../2026-10-16-srgg-classical-rom/direct-ibs.md) 条件路线；不把新推导写成原论文已经证明的定理。

新增 [hardness_search.py](../../../../experiments/research/candidates/srgg/hardness_search.py) 和 [对应测试](../../../../tests/test_srgg_hardness_search.py)。复用 [formal_candidates.py](../../../../experiments/research/candidates/srgg/formal_candidates.py) 的几何和 Zn smoothing，另显式筛选 [psf_bridge.py](../../../../experiments/research/candidates/srgg/psf_bridge.py) 所用 full-kernel GSO 条件。

工具为现有干净 [Lattice Estimator 53da598](https://github.com/malb/lattice-estimator/tree/53da5982597709ba0fdf94ea37a84d822310fd84)，执行前后检查 HEAD、Git 规范化内容和实际导入路径；没有安装或更新依赖。ADPS16 classical/quantum Core-SVP 成本，系数 LWE primal-uSVP 使用 LGSA，另跑 plain dual；欧氏 SIS 的源码明确忽略 shape 参数，报告没有把它写成 LGSA 验证。

实际环境：Intel Core Ultra 7 255HX；WSL Ubuntu-24.04、Sage 10.9/Python 3.13.15；纯算术测试另用 Windows Python。没有身份、消息或签名实例，没有 Gaussian 或密钥抽样，没有重复随机种子；每个确定性估计任务运行一次。最大每点预算 60 s，保留全部非有限结果和异常。

## 2. 估计输入不能混用

固定 `R_Q=Z_Q[X]/(X^n+1)`，`A=[I_d,Ahat,B]`，`M=(2+w)d`。

| 对象 | 本项输入 | 实际结构限制 |
|---|---|---|
| 单列 decisional Module-LWE | `n_lwe=m_lwe=dn`，Q，secret/error 均为 `CenteredBinomial(1)` | Ahat 是 d×d 环矩阵，展开是负循环块；各系数秘密/误差的 law 为 `(-1,0,1)` 上 `(1/4,1/2,1/4)` |
| shared-Ahat hybrid | wd 个单列区分器，各运行整个公开提取器 | 不能把其它列当作同一秘密的 wd 倍独立样本；hybrid 损失为优势之和 |
| HNF-MSIS | `dn` 行、`((2+w)d+1)n` 列，欧氏长度平方上界 `4 Bsig` | 真挑战是 `C=[I_d|U]`，U 均匀环矩阵，非独立标量条目矩阵 |

LWE uSVP 对应启发式 secret-search，dual 对应区分；SIS 对应短非零核搜索。把实际环矩阵按系数维数送入普通 LWE/SIS 模型，仅给通用攻击成本**对照**。它没有核验结构化矩阵的 GSA/LGSA，也没有覆盖环、子域、CRT、代数、BDD/hybrid、BKW 或 Arora–GB 攻击。因此高成本不能成为准入证据；低成本也不是已经在真实实例执行的攻击。

当 `Q²>4 Bsig` 时，整数非零差分不可能是全 Q 倍数；本项同时保留这项精确门。欧氏 SIS 不用逐系数无穷范数松弛，避免改变本项比较对象。

## 3. 既有点的结果

当前 `n512,d2,b31,w8,r²64,p16383`，Q=`13972913866395903`，单列 LWE 的 n=m=1024；HNF-MSIS 系数形状 1024×10752，`4Bsig=953022385920644398085744640`。

| 模型 | LWE uSVP log₂rop | LWE dual log₂rop | SIS lattice log₂rop |
|---|---:|---:|---:|
| classical | 30.660 | 31.536 | 57.524 |
| quantum Core-SVP | 27.825 | 28.622 | 52.205 |

这些数值不支持把此点定为正式安全实例。此前在它上面的真实发钥、签验、恢复、采样/分布证书仍是研究实现证据；本项没有反向删除那些交付，也没有将低成本估计称为已实现的公开伪造。

Q=`3·43·127·31^8`。因为 n 是 2 的幂、Q 奇，各素因子下 `X^n+1` 无重根；不可约因子次数为素数在模 2n 下的乘法阶。当前 n512 下，3/31/43/127 对应次数 256/32/256/8。报告记录每个搜索点的精确 Q 因子和这些次数。**次数不是投影攻击成本**：投影后的 CBD1 秘密/误差可能相关，不得继续当独立原 CBD1。投影到 Q 的任一因子都是攻击入口，但其具体 law、区分优势、向原问题的成本/成功率对应尚未算完。

## 4. 有限搜索设计与筛选

冻结搜索域：

- `(n,d)` 为 `(512,1/2/4/8/12/16)`、`(1024,2/4/6/8)`、`(2048,2/3/4)`、`(4096,2)`、`(8192,2)`。
- b∈{3,7,15,31,63}，w∈{2,…,32}，r²∈{64,128}；根始终是独立 CBD1。
- p 为 `[3,2^32−1]` 内与 b 互素的奇数。每个形状精确求满足 `Q²>4 Bsig` 的最小 p；不是用浮点求根或少数 p 网格代替。
- raw norm cap 沿用 `16·N·s_master²`；user cap 沿用 `2 Rcap+2dn(p−1)²`；master/signature 形状采用原充分正定界加 1。它们是明确的公开规划公式，不是已重新生成的大维采样概率证书。

记 `D=((2+w)d+1)n`。固定其它形状时 `Bsig=a(p−1)²+c`，故门为

```text
(b^(2w)−4a)p² + 8ap −4a−4c > 0.
```

程序处理凸、线性及凹二次式，先定位有限区间内递增段的可行根，再取第一个合法奇数 p。对应测试用独立 p 穷举核对。若最小 p 已无法通过 full-kernel 门，增加 p 只会增大该 GSO 上界，不能改善该形状。

除原几何和 `Q>2gamma` 外，必须同时满足

```text
beta_root = 1+2d²wn²,
GSO² <= max(p², beta_root(b²+1)),
s_master²/GSO² >= 相应 Zn-theta 充分条件.
```

这来自既有完整 kernel 基的 gadget/head/middle 排序；不使用一把实际私钥的观测谱界。r²64 对照要求至少 80-bit 相对正规化误差，r²128 搜索要求至少 192-bit；后者是为多查询统计账本保留余量，仍未实例化全部卷积/有限计算项。仅过 `formal_candidates` 的正定几何会漏掉 p² 门；本轮测试保留一个确实过几何而不过 full-kernel 的负控。

共 4,650 个形状，按每组 `(n,d,r²)` 中**最小 Q、平手选更小 D**保留 30 点，另加旧点，共 31 点/186 项估计。这个规则优先改善固定 dn 下的 Q/噪声比例；不是对完整 IBS 成本、MSIS、存储或整个参数空间的全局优化。不能据未选形状断言其无优势。

## 5. 值得继续核验的点与资源

以下 r²128 点通过本批充分几何及 192-bit full-kernel 筛选，仍是**未执行、未准入的候选**。表中成本只取本批所跑三个攻击族的有限输出最小值；这不能替代结构攻击。

| n/d/b/w/p | Q 位数 | 最小 classical log₂rop | 最小 quantum log₂rop | B+seed 模型字节 | 原始签名模型字节 |
|---|---:|---:|---:|---:|---:|
| 512/2/3/19/16429 | 45 | 43.216 | 39.220 | 见 JSON | 见 JSON |
| 512/4/3/20/23401 | 47 | 114.464 | 103.880 | 见 JSON | 见 JSON |
| 512/8/3/21/33329 | 49 | 271.560 | 246.450 | 见 JSON | 见 JSON |
| 512/12/3/21/74921 | 50 | 439.752 | 399.090 | 9,676,832 | 886,464 |
| 1024/6/3/21/106141 | 50 | 434.496 | 394.320 | 4,838,432 | 889,728 |
| 2048/3/3/22/53615 | 51 | 428.364 | 388.755 | 2,585,120 | 953,344 |

最后一行在这几个候选中有较小 B 载荷且 rank=3，可优先做下一轮结构攻击与资源验证；没有实测速度/峰值内存，不能称它最优或可用。新候选完整参数和所有误差对照字段见 JSON，不能只摘表中成本。

这些点超出现有 `ExecutionParams` 的 n/rank/w/p 资源范围，且较大的 N 超过部分冻结证书工具的 2^17 维 cap；本工具只做算术，没有越过旧执行器或 sampler 的限制。实际运行、完整有限采样、全服务和恢复必须重新验收。模型字节只计规范整数的假想固定宽度载荷，不包含 wire、Python/Sage 对象、缓存、序列化和容器开销，不是实测大小或峰值内存。

共 146 项返回有限成本；20 项 uSVP `KeyError: beta`，20 项 dual 无有限结果。它们全部出现在较大 dn 点，固定版本的相关优化器全局 `max_beta=1754`；LGSA 路径在基线未找到有限 beta 时会访问缺少的字段。**未超出工具域外推，没有把异常或 infinity 写成高安全。** 所有原始输出保留，搜索域有这些未决点，不宣称无解。

## 6. 归约损失与 Kyber/NIST 对标边界

由独立 classical-ROM 文稿，令 g=2^-n、kappa=2^(-n/2)、q=q_F、

```text
t=max(0,p−g),
F(p)=max(0,t²/(8q)−kappa*t/4).
```

完整原始游戏统计扣费为 Delta，身份预算 Q_I，hardness 总优势为 a，则条件结论可以反解为

```text
epsilon_IBS <= Delta + Q_I*(g+q*kappa+sqrt(q²*kappa²+8q*a)).
```

这只是相同运行预算下的优势关系。每个 MLWE 区分器运行完整 E，E 最多两轮 Run；重放的 sampler/哈希/字节预算不能按一次实跑缩减。MSIS 与 wd 个 MLWE 项也不能假定是同一攻击成功率或同一时间。

为了展示损失，JSON 另算一个**明确假设 Delta=0**的场景：若希望 IBS 优势≤2^-128，Q_I=q_F 分别取 1/2^20/2^40，则通过直接计算 `F(2^-128/Q_I)/(1+wd)`，给出每个 hardness 优势共同上界的充分 dyadic 位数。当前 wd16 时分别为 264/324/384；上述 n2048/d3/w22 为 266/326/386。n256、40-bit 查询预算下 F 为零，测试保留此熵负控。

**log₂rop 是估计工作的数量级，2^-lambda 是某时间预算下的优势上界；两者不能直接替换。** 表中 428 或 388 不能据此被减掉某个数字、再颁布 IBS 安全位数。要按 Kyber/ML-KEM 与 NIST 目标比较，仍需固定目标安全游戏、攻击时间/成功率、查询上限、统计总误差、资源和结构化困难性模型，并与标准对照采用一致成本模型。量子 Core-SVP 成本也不能补上 QROM 的相干 H1/重编程/重绕证明。此批没有授予任何 NIST category。

## 7. 运行与证据

在仓库根目录、指定 WSL Sage 环境：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.hardness_search \
  --estimator-path ~/lattice-estimator --output build/outputs/srgg-hardness-new.json
```

输出必须不存在，防止覆盖证据。不提供 estimator 路径时只生成算术和明确的空估计字段。工具检查干净固定版本；逐任务 checkpoint，超时/异常字段明确保留。

```text
python -m pytest -q tests/test_srgg_hardness_search.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_hardness_search.py
```

Windows/Sage 各 **24 passed**，不可相加成不同测试数。本批公开结果为 [finite-search.json](finite-search.json)，其 source hashes 绑定本工具和原几何模块。原始运行在 ignored `build/outputs/srgg-hardness-2026-10-16/finite-search-final.json`，独立早期探索和失败收据仍保留在同目录，不覆盖冻结批次。每点实际最长不足 4 s，全点估计合计约 42 s；这些是本机工具分析时间，不是攻击时间或密码学算法性能。

未实现/未完成：结构/CRT/子域攻击的实际 law 与成本，完整更大参数分布/有限误差账本，统计 Delta_0 的具体服务对应，新点资源准入和真实生命周期，安全时间/优势标定，QROM 证明与 NIST 等级判定。新的条件候选不能覆盖这些缺口。
