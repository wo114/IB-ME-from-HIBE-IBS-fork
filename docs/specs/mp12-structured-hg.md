# 结构化 MP12 / 完整 H/G 研究后端契约

此实现是 CHKP ROM 身份矩阵上的 **MP12 陷门/采样实现变体**，不是原 CHKP RandBasis，也不新增论文算法或困难假设类别。公开入口为 `ibme.hibe.mp12_structured`，默认选择 ID `mp12-structured-hg`，版本 `mp12-structured-hg-finite-v1`。原 `chkp`、完整基 `mp12-chkp-reference`、教学 `abb10` 和真实 `abb-rom` 分别保留。

## 算法、维度与引用

固定 [MP12 作者稿](../../papers/2011_lattice_trapdoors_micciancio.pdf) §5.4 / Algorithm 3 / Theorem 5.5、§5.5 / Algorithm 4 / Lemma 5.7，以及 [CHKP 作者稿](../../papers/2010_bonsai_trees_cash.pdf) §5.1–5.3。MP12 的理想分布结论不直接证明本有限实现或修改后的 HIBE 安全。

这里的 CHKP 作者稿与 EUROCRYPT 2010 出版版不是同一布局。出版版 §5.3 的深度 2 ROHIBE 只把 `A0 || H(rcv)` 的 `2m` 列送入 KEM，`G(rcv,phi)` 是终端 syndrome；Theorem 5.3 也固定 `dm`。当前版本下列 `3m` 全 LWE 叶来自作者稿的 `(t+1)m` 定义，而该稿自己的定理/模拟器仍按 `dm`，故不能直接继承其安全结论。出版版目标与强制不准入证书见[2026-10-17 交付](../research/team-a-delivery/2026-10-17-chkp-published-target/README.md)；现版本不静默改变对象或 wire。

设 `w=n·ceil(log₂q)`，根前缀 `p=2n`，`m=p+w`。根为计算型 `[I|Â]` 及实际有限离散高斯 R，`A=[Ā|G−ĀR]`，标签 H 固定单位矩阵。公开矩阵遵循原有规范 H/G 和两层身份 `(rcv, phi)`：

- 根 `A₀` 有 m 列；接收者矩阵 `[A₀|H(rcv)]` 有 2m 列。
- 叶矩阵 `[A₀|H(rcv)|H(rcv,phi)]` 有 3m 列；G 为 256 个带位置域分隔的目标。
- **H 的每一块始终 n×m，未缩成 n×w。**

`StructuredLeftSampler` 把扩展 E 放到原 gadget 前，将 R 补零行，得到 `[Ā|E|G−ĀR]` 的有效结构化陷门；实际 Algorithm 3 采样后，逆置换回 `[A|E]` 的坐标。所有输出坐标实际采样；不把零向量拼到原像。坐标置换是正交变换，保留球形高斯、范数和余类方程；有限实现误差按下述显式模型累计。

完整 H 委派将 H 的前 `m−w` 列用于上述 SampleLeft，最后 w 列用于 Algorithm 4：逐列采样 `A_ext·R' = G−H_tail`，产生恰好 `[A|H]` 的新结构化陷门。接收者后不再生成一个多余的终端陷门：直接对完整第二块 H 做 SampleLeft，固定采样 256 个目标原像。没有调用 ToBasis、完整核格基转换、Flatter 或原 CHKP RandBasis。

## 同组参数与门槛

预设 `n2-full-hg-research`：n=2、q=549755813911、根 R 平方宽度16、`qα=4`、原语身份最大86 B、接收者/子身份容量各2。只支持 raw 32 B seed，统一框架强制 Hybrid；应用可含空消息和任意合法字节，由既有 Hybrid/BYTEAUTH 承载。

| 项 | 固定公开值 |
|---|---:|
| gadget w / 根 m | 80 / 84 |
| 父采样维度 / 接收者矩阵维度 / 叶维度 | 88 / 168 / 252 |
| 根 R Frobenius 平方上界 B₀ | 5120 |
| 父采样平方宽度 | 28288000 |
| 接收者 R 平方界 B₁ | 199147520000 |
| 叶采样平方宽度 | 1083362509235200 |
| 全父委派 / 全叶随机带请求上界 B | 1462989752320 / 26907788083200 |

宽度来自公开声明的 B，而非实际有利的秘密谱：`r²=4·smoothing_factor(w,128)`；`s²=max(7r²(1+B),10r²(w+B))`；父每列检查 `||x||²≤88·s_parent²`，固定叶每个原像检查 `||x||²≤252·s_leaf²`。整父委派维持原工具 `2^44 B` 门，256 目标消费者使用既有 `CheckedEntropy` 上限 `2^48 B`；这些是最坏请求量，不是分配的内存或实际消费量。

所有标量沿用 tail128 / mass256 / precision320 / Gaussian-abort128；扰动最多512次；只展开40维 gadget 核基和受限 Schur 逆。rounded-continuous 噪声是独立、实际有向 CDF 的 `round(q·Gaussian_α)`，tail128 / mass256 / precision320。同组条件解码界在每位128 bits、256位、`2^20` 次封装下通过；原每位预算不能直接当成整段服务预算。

`mp12_bounds` 将 Theorem5.5 证明(5.1)的两个 normalizer 因子展开。令 `ε=2^-128`，卷积 TV 的具体保守上界为 `min(1,2ε/(1−ε)^2)`。证书新增 `distribution_budget` 和 `modeled_sample_TV_including_abort_upper`，累计有限球形 proposal、Bernoulli 量化、512次扰动中止及 n 个 gadget GPV；各标量自己的中止已计入其 TV。范数门另按 Poisson normalizer 和指数 Markov 得到 `(3/10)^D·(1+ε)/(1−ε)` 的向上 dyadic 界；所需目标余类 smoothing 用 Lemma5.3 的 `GS²≤10(B+1)` 与 Lemma2.3 检查。证明、前提与复核见[具体有限账本](../research/team-a-delivery/2026-10-15-finite-budget/README.md)。

同组最大2个接收者、4叶，共160次父 SampleD、1024次叶 SampleD；固定钥复用无新增采样。在 `2^20` 次封装、至多 `2^20` 个不同H地址和 `2^20` 条不同G路径的**理想随机流/正确有向算术模型**内，累计偏差或诚实失败上界落在 `(2^-98,2^-97]`。当前128-bit累计概率目标未通过，这个指数不表示LWE安全位数。实际 SHAKE 的随机预言机实现论证、机器/内存/熵源故障仍无总界；`full_sample_TV_or_failure_upper` 和完整实现/安全失败界保持null。公开参数投影也不替代每把真实陷门的精确算术路径准入。

prefix≤512、总列≤8192、R项≤2²²等原工具门未放宽；另预检全部固定树的最坏快照。对当前全部 n=2…128、模数位数2…61，以每区间最大q、最小合法根宽和噪声作15240个双口径乐观区间检查，完整H/G的必要条件仅容许 `n≤5`。通过区间还须核素性、随机带、快照、真实路径和困难性；该结果没有准入任何参数。n128/q65537 的旧2432维根仍只算根/原像诊断。进入正式困难维度须改变实际实现域与资源算法，单纯增加参数n不能越过本版本限制。

[完整同组目标筛查](../research/team-a-delivery/2026-10-16-target-parameters/README.md)另给出n128/512/2048/4096、q59/67/74/77位的公开数值投影及两个LWE角色。192位有限预算配方仅用于分析，未登记或实现为本后端profile，当前参数/wire/采样帽均保持v1。n4096的现有父R JSON最低209,278,992,384 B且q超uint64头；四组都被当前门拒绝。成本估算为Gaussian比较模型，不授安全等级。

## 对象、状态与错误

六方法为 `setup/extract/derive/encrypt/decrypt/load_ciphertext`，另有 Hybrid 所需 `validate_key_binding`。五对象为 `StructuredPublicKey/StructuredMasterSecret/StructuredLevel1Key/StructuredLevel2Key/StructuredCiphertext`，均有独立 framing，严格长度、版本、维度、规范整数和参数快照。密文不携带身份；完整参数与根矩阵绑定 H/G context。私钥恢复检查结构化陷门方程、声明界、父逐列范数和全部256个叶方程；不能据此证明采样来源或保密性。

成功地址复用同一对象/字节；新发钥前占用 pending/failed 地址，异常后容量不释放。接收者失败、叶失败和 pending 发布失败经过 codec 后仍拒绝重发；同址并发只允许一次尝试。可选 `persist_pending` 适用于受信单写者消费者；默认 CLI 另外提供锁和 commit-before-publish 事务。私钥快照是敏感明文，没有外部认证或防回滚保证。

解密只使用固定叶，恢复/复用/解密不需要新熵。raw seed CPA 层的错误身份可能得到另一串32 B；上下文/形状不符返回 None。完整协议拒绝使用既有 Hybrid AEAD 和 BYTEAUTH/IBS，返回公共 `BOTTOM`。raw 容错不被改写成全字节完整性。

## 安全与验收边界

n=2 的公开有限误差枚举在真实实例中恢复了全部32 B；它是负控，不提供 LWE 保密性。保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。除匿名 ROM、计算型根、固定发钥与具体有限采样的整体安全映射外，`3m` 实现与出版版 `2m` 定理的布局差异也尚未解决；不直接继承原 CHKP 定理，不声称 QROM、NIST 等级、标准模型安全或端到端加速。

同根真实2×2、五类对象、新进程零熵恢复、公共六种 IBS 配对和安装 CLI 的准确版本、重复次数、环境及失败记录见[本轮交付](../research/team-a-delivery/2026-10-15-framework-and-structured/README.md)。功能/统计测试不能替代安全证明。
