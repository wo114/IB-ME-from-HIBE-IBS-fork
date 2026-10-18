# CHKP 3m 紧凑委派运行原型 v1

2026-10-18增量：另有显式`RadixPrototypeParams`/`RadixPrototypeContext`，profile `IBME/MP12-RADIX-BLOCKED-3M/1`，radix_bits为2..32。它只扩展该根/父/256叶原型，不登记完整HIBE；本轮按剩余4天交付约束进行有界实测。以下二进制v1仍保留默认与原参数字节。

该原型消费作者稿两层 CHKP 的完整 H/G：`w=n ceil(log2 q)`、`m=2n+w`，根 `n×m`、父 `n×2m`、叶 `n×3m`，固定叶实际采样 256 个位置。继续使用 MP12 Algorithm 3/4；没有切换 published 2m，也没有新增论文算法计数。代码入口为 `src/ibme/hibe/mp12_structured/blocked_prototype.py`，运行入口为 `experiments.research.blocked_3m_probe`。

这是**根、父、固定叶及对象恢复的工程原型**。后续已新增独立的[高基数 3m 种子 KEM](../../src/ibme/hibe/mp12_structured/radix_kem.py)，用实际有限舍入噪声完成 n=2/q93/b1024 的根→父→256叶→种子加解封装定向运行；它仍未登记共同 HIBEBackend，也没有 Hybrid/CLI 或完整 IB-ME 成功声明。该 MP12 紧凑陷门实现不与完整基/RandBasis 路线混算证据，现有 structured HIBE v1/v2、注册和 wire 保持原样。

## 运算与表示

- 大模数使用现有 `PrimeGadgetSampler` 的完整二进制 gadget，各块只准备 `k×k` 公开基；q 为已证明奇素数，最多 256 位，计算不经过 uint64。
- 私有 R 保存**全部实际采样坐标**，按列编码；有符号二补码的固定字节数由公共坐标界决定，不按观察到的私钥最大值选宽度。父仅保留自身 R 与公开矩阵，不保留主 R、其生成随机带或指向主对象的引用。
- `PackedMatrix` 的规范版本单独标识。有界 native 列块用于 `R*x` 和 `Rᵀ*x`，不展开完整转置、完整核基或稠密 Schur 逆。打包的字节底层仍在内存中；**本版不是 mmap 或完整 out-of-core 实现**。块缓存预算是保守估算，实际 RSS 另测。
- SampleLeft 按 `[A|E]` 原顺序运行。J 为 `[R; I; 0]`，对 E 的输出来自完整球形扰动，不能把 J 的零行解释成输出补零。

设 `S=s²`、`g=5r²`、`v=Jᵀp`。接受指数为

```text
(g/S²) vᵀ (I-(g/S)JᵀJ)^(-1) v.
```

固定点迭代只构造候选解；以整数精确计算残差，利用声明的 `g(1+B)/S≤1/2` 给出该二次型的有理区间。区间误差达到公开阈值后，使用 MPFI 定向指数计算接受权重，逐次检查权重区间宽度不超过现有 finite scalar 的误差预算。达到迭代/区间/熵限制即中止，没有近似接受、对角替换或分布回退。独立小实例测试直接求完整协方差逆，核对该区间。

## 参数与边界

原型配方固定 epsilon/tail/abort=192、mass=320、precision=384、uniform trials=256、扰动最多512轮；H/G 仍使用现有128次有界 residue rejection，显式记录，不能据此冒领历史192次投影的累计概率。根平方宽默认8n，`qα=max(4,floor(2sqrt(n))+1)`，同组完整3m宽度及条件噪声不等式在入口核对。概率记账复用既有 MP12 条件项；算术迭代、进程资源与整操作熵帽中止的概率没有获证，不能把条件项当总失效率。

每个矩阵至多 `2^24` 项、512 MiB，完整叶维数至多8192；完整树入口提前筛查父 R 和256个叶原像。每次父/叶操作实际耗熵另受显式帽约束，默认 `2^40` B，超出后中止。有限采样器自己的每调用随机带界保持不变。固定坐标界、规范输入、维度、模数、公钥/身份上下文、陷门方程和范数在加载时检查。

运行必须指定全新的私有目录。根/父/叶在采样前 fsync occupied/pending 标记，失败保留标记和部分产物，不自动重抽；完成后保留 done 地址。恢复只读取已有对象、验证根/父关系和256个叶方程，不生成新钥或原像。该研究探针不是共同 CLI 事务、防回滚存储或加密私钥容器。

## 声明与测量

按用户当前工作前提，所选论文算法安全、HIBE 身份匿名；本版继续完成参数、实现和资源核验，不新增安全/匿名证明任务。所有结果保留 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`；教学 n 不代表目标安全参数，功能测试不替代论文结论。

实测使用指定 WSL `~/miniconda3/envs/sage/bin/python`，默认系统 CSPRNG；固定 TEST 熵只出现在测试。每阶段报告耗时、10 ms `/proc` 进程树 RSS 采样、内核累计 RSS 高水位、持久对象字节数和中止。采样 RSS 可能漏掉短峰值；累计高水位不冒称阶段独立峰值。完整评测数据与结论由 A 交付目录记录，`blocked_3m_projection` 只重算既有目标参数的编码字节数，不生成目标私钥、不补做安全估算。

## 显式高基数增量

`prime_gadget_kernel`、`PrimeGadgetSampler`、`generate_root`、`PackedTrapdoor`新增keyword `radix_bits=1`；默认保持二进制。令b=2^a，k=ceil(log_b q)，w=nk，t=b²+1。公开核格基使用b e_i−e_(i+1)和q的base-b digits，完整行列式q与GPV条件仍实际核验；g=t r²，输出平方宽为`max((t+2)r²(1+B),2t r²(w+B))`。根方程、逐列父委派和最终Rz全按同一b，父继承该基数。现有完整扰动、精确残差/权重区间、范数与资源中止保持；不补零、不省略H列。

高基数原型的context/object magic与版本均独立，参数快照包含radix_bits，H/G上下文绑定该完整快照；相同矩阵形状也不能混读不同基数。父只保存自己的R；恢复按声明基数验证`A[R;I]=G_b`以及256叶全部方程。原二进制参数dataclass不增加序列化字段，旧收据参数快照仍逐字节对应。未改structured HIBE v1/v2、registry、默认CLI或协议。

命令为既有`experiments.research.blocked_3m_probe --radix-bits 12`，默认1仍为原路径。每次指定新私有目录，失败/pending不重发。本轮每个实测调用外部GNU `timeout --signal=TERM --kill-after=10s 300s`，结束后只读恢复；超时保留原pending，单列为本次预算未完成，不据此否定算法。n4096/b4096/q93候选仍保留，但未放宽原型2^24项/8192维的运行门槛或启动高维钥生成。实际n属于研究小参数，同q或同基数不能继承目标困难性。后续是否继续实现完整KEM/后端，按当前四天交付安排和实测收益决定。
