# A0：CHKP 出版版布局参数目标与强制不准入证书

本批给出一个完整数值候选，并查明现有 `mp12-structured-hg` 不能继承所引用的 CHKP 出版版定理。结论不是“后端已获得正式安全参数”：候选的数值门全部通过，但证明—实现映射、实际资源门和完整攻击覆盖没有闭合，故保持

```text
security_claim=none
backend_admitted=false
parameters_are_formal=false
paper_parameter_set_formal=false
```

新增筛查器把“数值候选完整”和“正式安全准入”分成不同字段，不能用前者替换后者。没有生成高维矩阵、根、主密钥、接收者钥或叶钥，没有读取项目随机源。公开证据为 [formal-target.json](evidence/formal-target.json)。

## 1. 原文版本冲突和集成决定

固定的 EUROCRYPT 2010 出版版来自 `https://people.cs.rutgers.edu/~dc789/bonsai.pdf`，SHA256 为 `87b5bff448f4e653bb7959a62c2b56c03ca495076678014b5dc8b7c90a90442f`。其 §5.3 将深度 `t` 的 ROHIBE 矩阵定义为

```text
A_id = A0 || A1 || ... || A_(t-1),  dimension = t*m
```

所以项目固定身份 `(receiver, sender)` 在深度 2 时只使用 `A0 || H(receiver)`，终端目标为 `G(receiver,sender,bit-position)`。Theorem 5.3 的 KEM 挑战维度同为 `d*m`，模拟器只猜 `d−1` 个 H 前缀。论文中的 `aid-ind-cpa` 是 adaptive-identity IND-CPA，不是匿名性的缩写；跨层匿名另依赖 LWE 伪随机性和独立均匀填充。目标保守地保留 `(d+1)m=3m` 传输前导，其中只有 `2m` 是 LWE 前导，最后 `m` 不参与解密或 Estimator 样本。

仓库固定作者稿 [2010_bonsai_trees_cash.pdf](../../../../papers/2010_bonsai_trees_cash.pdf) 的 SHA256 为 `b1d8a2ae0e9d4e5c9145bbc6dc864090605c12a5b76149aa0684d62a8815d2ce`。该稿把 ROHIBE 写成 `(t+1)m`，但同一定理仍使用 `dm`，证明仍只解析到 `A_(d-1)`；两处不能同时作为当前 `3m` LWE 叶的证明依据。现后端确实实现 `A0 || H(receiver) || H(receiver,sender)`，并用全部 `3m` 分量加 LWE 噪声。

集成决定是：不静默改变已有 wire、对象或身份语义，不把出版版定理贴到现后端；后续如实施出版版路线，应使用新版本对象/后端并重新完成协议验收。这个差异也已写入 CHKP/结构化后端契约。

## 2. 完整数值候选

候选 ID 为 `chkp-published-rom-mp12-computational-n6144-v1`，身份顺序固定为 `(receiver, sender)`，最大身份 86 B，种子 32 B，服务预算为 `2^20` 次封装、每层至多 `2^20` 个 H 查询、每个 bit-position 至多 `2^20` 条 G 路径。

| 项 | 数值 |
|---|---:|
| LWE 维度 `n` | 6144 |
| 已证明素数 `q` | 667066744249733736124919（80 bit） |
| gadget 宽度 `w=n·ceil(log2 q)` | 491520 |
| 根列数 `m=n(k+2)` | 503808 |
| 出版版深度 2 的实际 LWE 前导 | 1007616 = `2m` |
| 匿名均匀填充 / 总传输前导 | 503808 / 1511424 = `m` / `3m` |
| terminal syndromes | 256 |
| 根 R 平方宽度 | 24577 |
| 父输出平方宽度 | 1258772133131059200 |
| 叶输出平方宽度 | 2707787999830205621663929702809600 |
| scaled noise `qα` | 157 |
| normal-form 密文比较样本 | 1001728 = `2m−n+256` |

`q` 由 Sage 证明为素数。它沿用原 `3m` 目标筛查的保守选择，再按出版版 `2m` 解密维度复核正确性；没有宣称它是 `2m` 路线的最小模数。根宽和密文噪声宽均严格超过 `2sqrt(n)` 的数值前提，现行整数相位/舍入/连续噪声充分式通过。上述只闭合公开数值条件，不自动闭合 CHKP 的渐近 `negl(n)`、MP12 替代分布或 LWE 困难性。

## 3. 有限概率和归约损失账本

192-bit 分配沿用既有公开有限采样组件，并新增安全模拟器和匿名 wire 以前遗漏的调用：

- 最多 `2·2^20` 个受控 H 根；
- 多 bit G 模拟为 `256·2^20 = 2^28` 个高斯向量；每个按最大 `2m` 维计，共 `270,479,860,432,896` 个有限标量；
- 每次封装额外 `m` 个均匀匿名填充系数。

投影总 TV／诚实失败上界仍落在 `(2^-132,2^-131]`。主要新增项的 dyadic 指数为：受控 H 根有限标量 137、受控 G 有限标量 143、G 理想像均匀性分配 164、匿名填充拒绝 153。`2^-131` 是声明模型中的概率上界，不是 LWE 安全位数。CHKP Lemma 2.4(4) 的渐近常数尚未被一个原文明确的有限常数替代，所以该分配明确标成 projection，`full_proof_finite_bound_admitted=false`。

查询损失分别记账，不把独立 hybrid 相乘两次：

| 路线 | 因子 / log2 |
|---|---:|
| CHKP Theorem 5.3，`d·QH^(d−1)·QG` | `2^41` / 41 |
| 256-bit hybrid | `2^8` / 8 |
| 自适应身份密文 LWE 合计 | `2^49` / 49 |
| 两端匿名比较的保守额外 hybrid | `2^50` / 50 |
| 主根及全部受控 H 根的 `w` 列 | 1030792642560 / 39.906891 |

根 LWE hybrid 与密文 LWE hybrid 是不同归约分支，未错误相加为同一个损失。

## 4. 固定 Estimator 比较模型

使用干净的 [Lattice Estimator](https://github.com/malb/lattice-estimator/tree/53da5982597709ba0fdf94ea37a84d822310fd84)，固定 commit `53da5982597709ba0fdf94ea37a84d822310fd84`。模型为 ADPS16 classical/quantum Core-SVP；执行 primal-uSVP（LGSA）、primal-BDD（LGSA）、dual、dual-hybrid，共两个 LWE 角色×两种成本模型×四种攻击 = 16 个确定性配置，每个配置执行 1 次，全部返回有限结果；没有把它们当作运行时间 benchmark。

| 角色 | 最小 classical log2(rop) | 最小 quantum log2(rop) | 扣除声明损失后的最小值 |
|---|---:|---:|---:|
| MP12 normal-form 根 | 310.396 | 281.695 | 241.788 |
| 出版版 `2m` 密文视角 | 308.644 | 280.105 | 230.105 |

这是理想离散 Gaussian 比较模型。实际密文使用有限 rounded-continuous Gaussian；coded-BKW、Arora-GB 和代数/结构攻击仍未闭合，不把 error、超时或 unknown 当作高成本。因此即使已测子集扣损失后超过 128，仍保持 `concrete_128bit_claim_admitted=false`、不声明 NIST 等级。

## 5. 资源拒绝

数值候选不能由当前后端执行。仅按现表示的公开下界：

| 对象 | 最低字节数 |
|---|---:|
| 根 R JSON | 12079595520（约 12 GiB） |
| 单父 R JSON | 507343011840（约 473 GiB） |
| 公共根 residues | 30953963520（约 29 GiB） |
| 单个固定 256-target 叶 wire | 1547698176（约 1.5 GiB） |
| 出版版 `2m` raw capsule residues | 10078720（约 9.7 MiB） |
| 含保守匿名填充的 capsule residues | 15116800（约 15 MiB） |

此外 `n>128`、80-bit `q` 超过现 61-bit/uint64 门，维度、R 项数、公钥、固定叶及 Hybrid 4 MiB 门全部失败。没有构造这些对象，也没有把存储下界冒充峰值 RSS 或运行时间。

## 6. 测试、环境与剩余工作

本机规定路径 `~/miniconda3/envs/sage` 不存在；本次实际使用 Nix 提供的 SageMath 10.9 / Python 3.14.7，Linux 6.18.56 x86_64，Intel Xeon Silver 4216（分配 12 核/12 线程）。该环境差异不隐藏，合并前仍应在项目规定的 WSL conda Sage 环境复跑。执行命令：

```sh
XDG_CACHE_HOME=/tmp/ibme-nix-cache nix-shell -p sage python3Packages.pytest --run \
  "PYTHONPATH=$PWD/src:$PWD sage -python -m pytest -q tests/test_chkp_published_formal_screen.py"

XDG_CACHE_HOME=/tmp/ibme-nix-cache nix-shell -p sage --run \
  "PYTHONPATH=$PWD/src:$PWD sage -python -m experiments.research.chkp_published_formal_screen \
   --estimator-path /tmp/ibme-lattice-estimator --output <新路径>/formal-target.json"
```

新增专项结果为 **10 passed / 0 skip**；相关仓库 `a-structured-hg` CI 目录在最新主线另为 **186 passed / 0 skip**，见 [JSON](evidence/a-structured-hg.json) 与 [JUnit](evidence/a-structured-hg.xml)。证据生成执行16次声明的攻击比较，未生成正式候选密钥或读取项目熵；CI 目录会复跑既有小型研究采样。功能测试和攻击未成功不能替代安全证明。

要把标准字段改成 formal/admitted，至少还需：实现并版本化出版版 `2m + uniform padding` 路线；证明 CHKP RandBasis 或等价秘密钥分布，而不是直接继承当前 MP12 DelTrap 对象；给 Lemma 2.4(4) 和字面 rounded-noise 完成有限映射；解决数百 GiB 级表示/算术和现 wire 门；补完攻击族；最后再做 Wang 组合的固定服务及端到端条件核验。本 PR 不以假声明绕过这些工作。
