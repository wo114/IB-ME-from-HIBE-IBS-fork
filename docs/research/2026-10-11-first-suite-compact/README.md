# 首套有限 DelTrap 链与困难性/资源筛查

基点79256ba，2026-10-11。上一轮发现n=1可公开恢复种子，因此本轮同时推进实际委派路径和正式尺寸的攻击/资源筛查。目标仍未完成。机器结果见 [实际链路](compact-chain.json)、[六组尺寸及估算](parameter-resources.json)、[交付/测试审计](audit.json)。

## 已实现的具体变化

MP12 [原稿](../../../papers/2011_lattice_trapdoors_micciancio.pdf) §5.5 Algorithm4 / Lemma5.7 提供DelTrap：对 `[A|A1]`、最后w=nk列，独立抽样满足 `A R'=G-A1` 的Gaussian列。本轮用既有FirstFiniteGPV作真实有限/CSPRNG oracle，增加明确列范数中止。不同于CHKP RandBasis，它不进行秩检测和ToBasis，也不将原根陷门补零后交给接收者。

`split_extension`将任意超出nk的扩展列放入采样前缀，最后nk列作A1。输出保存矩形G-trapdoor：严格私有JSON wire、外部给定的真实公开矩阵/宽度绑定、定义关系与列范数检查。加载只验证数学和格式，不证明原始抽样来源。需要完整基时用既有qFALL私有接口作确定性转换，重新核验完整核格/GS；**没有采用库未经核验的随机源，也没有实现MP12 Algorithm3扰动采样**。

这是独立 `MP12-DELTRAP-PILOT/1` profile，不将它改名为原CHKP/RandBasis，不改旧发钥树地址或原采样guard。主状态新增显式私有研究输入出口，使调用方不读取内部字段；出口只有持有主私钥的调用方可用，返回已验证的不可变根基，不发钥、不修改状态。队友chkp_*、旧GenTrap、旧public-test前端及src后端未改。

## 分布、范数与声明

原论文的理想DelTrap列分布与输入陷门无关。本轮的有限适配比较的是相同公开矩阵、宽度和列范数中止规则下的输出：w次oracle误差并集，含采样中止；不同有效有限oracle的输出比较仍需两边误差之和，不能称精确独立。

以每列 `||r_j||²≤s1²·p` 给出公开Frobenius界，再由MP12 Lemma5.3导出：

```text
delegated_full_basis_GS² <= 10*(1+w*p*s1²)
```

这是保守充分界，不能替换成未核定常数/坏事件的更小谱范数。Gaussian列坏范数事件沿用既有GPV/RandBasis的陪集尾界条件，采样TV另列。公开TV用标量profile整体范围给上界，不公开秘密基逐坐标GS/宽度/中心证书。此次父中止上界约2^-113.210；实际与有界理想输出TV约2^-113.985，范数坏事件并集约2^-114.476。它们不是安全等级或全HIBE证明。

**CHKP公钥矩阵/H/G及加密布局可以复用，但返回密钥和委派算法已变。** Lemma5.7覆盖委派分布，不能直接宣称CHKP Theorem5.2原封不动覆盖这个变体；ROM查询模拟、替代密钥分布和同组参数条件还须引用/对应核验。不开展完整基础证明重做；如有必要的适用条件缺口，仍必须保留。

## 实际同组链路

原根来自上轮保存的OS CSPRNG主状态，n=1 / q=35184372088891 / m=83。通过显式出口复用同一个完整根，不重新GenTrap。独立公开配置使新profile的H/G与原RandBasis地址区别开。

| 项目 | 实跑结果 |
|---|---|
| 根 / 父 / 叶维度 | 83 / 166 / 249 |
| DelTrap采样前缀 / Gaussian列 | 120 / 46 |
| 父矩形陷门 / 完整基系数数 | 5520 / 27556 |
| 父私有wire | 50656 B；完整基现有binary格式严格最低165336 B，后者非实测基线 |
| 叶固定原像 / wire | 256个 / 574449 B |
| s1² / 父完整基公开GS² | 272729642840 / 15054676284768010 |
| s2² / epsilon_bits | 8249962604052869480 / 128 |
| 父 / 叶实际随机bytes | 2282281 / 27819627 |
| 叶256原像公共TV并集上界 | 约2^-110.455，含有限采样中止 |
| 根 / 父 / 叶新生成次数 | 0 / 1 / 1 |
| 真实噪声种子封装 | 两个OS随机32B种子，512bit / 0错误 |
| 原身份 / 编码身份 | Bob/Alice 3/5B；内部86B |
| raw capsule / alpha | 3127 B / 4/q |

全过程约46.490s，包含旧根加载、独立预定精确LLL、构造、委派、256叶抽样、状态与两次封装，不是公平算法或完整IBME基准。新解释器恢复父wire和叶wire均字节一致、种子散列匹配，生成次数0；不调用native转换或RNG。一次批次/两个封装不替代理论可靠性。私有R、基、原像、熵bytes和种子不进入Git。

父/叶都是真实有限CSPRNG路径；原来的有限RandBasis大父级仍没有因此被验收。这套profile也还不是七入口/CLI后端。n=1仍可被上一轮公开攻击，`security_claim:none,backend_admitted:false,parameters_are_formal:false`；首套准入数0，旧education两个认证反例未修复。

## 正式尺寸为什么不能仅换n

使用[固定Lattice Estimator](https://github.com/malb/lattice-estimator/tree/53da5982597709ba0fdf94ea37a84d822310fd84)，[primal-uSVP源码](https://github.com/malb/lattice-estimator/blob/53da5982597709ba0fdf94ea37a84d822310fd84/estimator/lwe_primal.py)，ADPS16经典/量子Core-SVP、LGSA。q=2^61−1已验素；R的实际有限质量>31.9，按该下界规划根统计目标128。消息误差宽度选择覆盖2sqrt(n)的下一幂2，仅是必要条件/诊断设置，不是安全参数。

均匀模q secret，样本数3m+256（已知候选明文可去除末端bit位移），记录工具normal-form转换后的分布和样本数。估算误差采用 `sigma=alpha*q/sqrt(2*pi)` 的Gaussian比较模型，**不是对实际取整连续Gaussian PMF的定理**。只跑uSVP，没有实际恢复这些高维密钥，也没覆盖dual、BKW、代数及其它攻击；Core-SVP不是现场时间或安全等级。

| n | 误差宽度 | 根m | uSVP经典/量子log2 Core-SVP | 矩形父陷门当前JSON的严格最低B |
|---|---|---|---|---|
| 128 | 32 | 9428 | 11.972 / 10.865 | 345051136 |
| 256 | 32 | 18799 | 11.972 / 10.865 | 1373083648 |
| 512 | 64 | 37542 | 11.972 / 10.865 | 5478342656 |
| 1024 | 64 | 75026 | 33.580 / 30.475 | 21884387328 |
| 2048 | 128 | 149995 | 105.120 / 95.400 | 87480582144 |
| 4096 | 128 | 299931 | 266.596 / 241.945 | 349804396544 |

JSON每个整数至少“引号+0+分隔符”4B；原完整基/叶signed-length格式每整数至少6B。省略行/头、实际大整数、对象和临时内存，所以都是下界。早期将旧6B口径用于新JSON得到525GB，已公开校正为约350GB，源码/归档统一；没有改变攻击成本或生成任何新密钥。不能把数据当完整组合排名或A+B<C证据。

全部尺寸超出现有根/GPV/私有格式实现范围；2048仍未达到模型128，4096单个uSVP估算高也不能放行。大的维度/宽度还影响噪声和标量资源；叶超过既有检查器65536域的行明确省略条件噪声检查，而非默认通过。未生成这些高维密钥，未改任何guard。

## 下一项及闭环剩余要求

第一套当前具备真实有限父/叶链，困难性和资源仍未合并成可执行参数。下一项先核验**MP12 §5.2 已发表的更小根路径与gadget取参**，联合记录根生成所需LWE（若采用计算型根）、密文LWE、GS/坏事件、噪声和实际代码/内存；不按维度单独选参，不把调整gadget计为新算法实例。较小矩形表示自身不足以解决当前大参数的体积和采样成本，Algorithm3/适用的现成数值代码还需真正接入核验。

取得可运行同组路径后，继续唯一发钥/失败持久化、原语模型引用对应、HIBE七入口/字节/公私绑定，与已实现Luo/HYBRID/Wang/BYTEAUTH集成；验收四种匹配、公开伪造、接收者重签、完整字节攻击与跨进程状态，再做完整系统成本。备用候选/独立优化后置。目标保持进行中，不能用本轮组件成绩重定义完成。

## 复验与问题修复

```bash
PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -m experiments.research.first_suite.compact_delegation_probe \
  --source-manifest test-results/first-suite-private-root-closed/private/public-restore-manifest.json \
  --private-directory test-results/first-suite-compact-new/private \
  --output test-results/first-suite-compact-new/result.json

PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -m experiments.research.first_suite.parameter_resource_probe \
  --estimator-path test-results/lattice-estimator --output test-results/first-suite-parameters-new.json

PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -m pytest -p no:cacheprovider -q --tb=short \
  tests/test_first_suite_compact_delegation.py tests/test_first_suite_root_generation.py \
  tests/test_first_suite_delegation.py
```

最终新增17项通过，相关回归157 passed，Windows36 passed / 2 skipped；批次重叠，最后追加桥接/类型检查后重跑受影响17项。CI仅收集这些Sage检查的skip，不能称CI跑过真实DelTrap。原基点79256ba两CI任务已成功。

初次真实探针转换函数导入不匹配，调整为独立private_basis_bridge，旧GenTrap源保持；第二次在抽样前发生Python Fraction与Sage QQ的比较错误，显式转换QQ后修复。确认没有生成父钥/消费其熵后，保留旧pending现场，在新目录开始实际一次生成；不因观察超时重启。真实key完成后恢复基于已有文件，失败不重抽。软件Sage10.9/Python3.13.14，指定WSL `~/miniconda3/envs/sage`，CPU Intel Core Ultra9 275HX；详细命令/散列/缺口见audit。
