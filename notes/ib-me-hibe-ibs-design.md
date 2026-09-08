# 基于两层 HIBE 与 IBS 的格基身份基匹配加密实现设计

- **作者**：根据王玥俊博士论文第三章、Boyen–Li 论文整理
- **年份 / 来源**：指导论文第三章；Boyen and Li，ESORICS 2023，本地文件
- **阅读日期**：2026-09-08 ｜ **深度级别**：标准级

---

## 1. 导读

这个课题要实现一种“双方都要点名才能解密”的身份基加密。发送者用自己的身份签名，并指定接收者；接收者只有在自己的身份和发送者指定的身份都相同时，才能解出消息。实现时最稳妥的路线是先把抽象构造跑通，再把两个黑盒替换成格密码：两层匿名 HIBE 负责把“接收者身份”和“发送者身份”绑定进密文，IBS 负责证明密文确实由该发送者生成。

需要先区分两份材料。指导论文第三章的构造 3.3.1 是直接的 `HIBE + IBS` 方案；978-3-031-51476-0_21 的 Boyen–Li 构造是 `匿名 IBE + IBS + ReExt + Ext`，解决的是更强的增强隐私。比赛项目应把第三章版本作为主线，把 Boyen–Li 版本作为后续扩展，避免算法、性质和实验口径混在一起。

*下一层：先说明两种构造分别解决什么问题。*

---

## 2. 背景与问题

普通 IBE 只让接收者身份参与匹配：拥有身份 $\rho$ 的人可以解出发给 $\rho$ 的密文。IB-ME 还让发送者主动指定 `snd`，因此解密条件是 $\rho=rcv$ 且 $\phi=snd$。其中 $\phi$ 是真实发送者身份，$\rho$ 是真实接收者身份，`rcv` 和 `snd` 分别是加密时指定的接收者、解密时尝试的发送者。

直接把两层身份写成 $rcv\mathbin|\phi$ 就能实现匹配，但还缺少来源认证：攻击者可能构造一个格式正确、却不是 $\phi$ 生成的密文。IBS 的签名补上这一点。

两份论文的差别是隐私目标不同。第三章构造主要依赖 HIBE 的匿名性；Boyen–Li 进一步要求即使接收者身份正确、但发送者猜错时，发送者身份和消息也保持隐藏，因此需要 `ReExt` 和 `Ext` 对 HIBE/IBS 组件做一次掩码。

*下一层：用一个具体故事看懂“绑定”和“认证”各自做什么。*

---

## 3. 核心思想

可以把 HIBE 看成一个两道门的保险箱。第一道门是接收者身份 `rcv`，第二道门是发送者身份 $\phi$。发送者把 $(t,m)$ 放入身份 $rcv|\phi$ 下的 HIBE 密文，其中 $t$ 是对 $rcv|m$ 的 IBS 签名。接收者持有第一层密钥 $\mathsf{sk}_{\rho}$，解密时临时选择 `snd` 并派生第二层密钥 $\mathsf{sk}_{\rho|snd}$。只有两道门同时匹配，HIBE 才能取出 $(t,m)$；随后 IBS 再检查 $t$ 是否真的是 `snd` 对 $\rho|m$ 的签名。

例如发送者 $\phi=$ Alice、接收者 `rcv` = Bob。密文实际加密在 Bob|Alice 下。Bob 选择 `snd` = Alice 时，HIBE 取出签名和消息，IBS 验签通过；Bob 选择 Carol，或者 Carol 拿到自己的第一层密钥，即使 HIBE 算法返回了某些数据，也会在身份/签名检查处失败。

Boyen–Li 版本把这两个“可见的绑定信号”再加密一次：用 `ReExt(K1,\phi)` 掩盖 IBE 密文，用 `Ext(K2,r)` 掩盖 IBS 签名。匹配时双方能恢复掩码；不匹配时掩码看起来像随机串，因而连发送者身份也不会泄露。

*下一层：登记符号，然后给出可直接编码的算法。*

---

## 4. 技术构造逐步讲解

### 4.1 符号表

| 符号 | 含义 | 人话说明 |
|---|---|---|
| $\lambda$ | 安全参数 | 控制矩阵维度、模数和安全级别 |
| $ID$ | 身份空间 | 建议使用固定长度字节串，先哈希到矩阵输入 |
| $\phi$ | 发送者真实身份 | 生成 IBS 加密密钥 |
| $\sigma$ | Boyen–Li 记号中的发送者身份 | 与基线版的 $\phi$ 相同 |
| $\rho$ | 接收者真实身份 | 生成 HIBE 第一层解密密钥 |
| `rcv` | 加密时指定的接收者 | HIBE 第一层身份 |
| `snd` | 解密时尝试的发送者 | HIBE 第二层身份和 IBS 验签身份 |
| $t$ | IBS 签名 | 对 `rcv || m` 的来源证明 |
| $\mathsf{sk}_{\rho|snd}$ | HIBE 派生密钥 | 由接收者选择 `snd` 临时生成 |
| $\bot$ | 失败符号 | 身份不匹配、验签失败或密文格式错误 |

### 4.2 第三章基线版：两层 HIBE + IBS

依赖组件：两层匿名 HIBE `HIBE = (Setup, Extract, Derive, Enc, Dec)`，以及 IBS `IBS = (Setup, KeyExt, Sign, Verify)`。HIBE 的消息空间必须容纳 `(signature, message)`；IBS 的消息编码必须固定且无歧义，例如 `Encode(rcv) || Encode(m)`。

```text
Setup(λ):
    (hpk, hmsk) ← HIBE.Setup(1^λ)
    (ipk, imsk) ← IBS.Setup(1^λ)
    return mpk = (hpk, ipk), msk = (hmsk, imsk)

SKGen(msk, φ):
    return ek_φ = IBS.KeyExt(imsk, φ)

RKGen(msk, ρ):
    return dk_ρ = HIBE.Extract(hmsk, ρ)

Enc(ek_φ, rcv, m):
    t ← IBS.Sign(ek_φ, Encode(rcv) || Encode(m))
    hct ← HIBE.Enc(hpk, (rcv, φ), Encode(t) || Encode(m))
    return ct = hct

Dec(dk_ρ, snd, ct):
    if ct cannot be parsed: return ⊥
    dsk ← HIBE.Derive(dk_ρ, snd)
    (t, m') ← HIBE.Dec(dsk, ct)
    if Decoding failed: return ⊥
    if IBS.Verify(ipk, snd, Encode(ρ) || Encode(m'), t) = 0: return ⊥
    return m'
```

正确性来自两个条件同时成立。若 $\rho=rcv$ 且 `snd` = $\phi$，派生出的 HIBE 身份正好是 `rcv|\phi`，因此能恢复 $(t,m)$；再因为 $t$ 是 $\phi$ 对 `rcv||m` 的合法签名，IBS 验证通过。任意一个条件不成立，都应返回 $\bot$。

### 4.3 格基 IBS 实例

建议按指导论文构造 3.4.1 实现改进版 SIS-IBS。核心数据是公共矩阵 $A\in\mathbb{Z}_q^{n\times m}$、 gadget 矩阵 $G\in\mathbb{Z}_q^{n\times n\lceil\log q\rceil}$ 和身份扩展矩阵
$$
F_{id}=[A\mid H_1(mpk,id)],\qquad H_1(mpk,id)=A\widehat R_{id}+G.
$$

`KeyExt` 用主陷门 $T_A$ 通过 `DelTrap` 得到 $F_{id}$ 的陷门 $T_{id}$。签名先计算
$$
h_2=H_2(mpk,id,m),
$$
再用 `SamplePre` 采样短向量 $z$，满足
$$
F_{id}z=h_2\pmod q.
$$
验签检查 $z\neq 0$、矩阵等式成立，以及
$$
\lVert z\rVert\leq s'\sqrt{m+n\lceil\log q\rceil}.
$$

这里的实现重点不是把高斯采样写成普通均匀随机数，而是保持 `TrapGen`、`DelTrap`、`SamplePre` 的离散高斯分布和范数界。可先用 Sage/Python 做正确性原型，再把采样和矩阵乘法移到 C++/Rust；WSL 中按项目要求使用 `/home/youzi/miniconda3/envs/sage` 环境运行 SageMath。

### 4.4 格基两层 HIBE 实例

HIBE 建议直接按 Agrawal–Boneh–Boyen 2010 的固定维度基委派方案实现，不要另造一个“能运行但没有论文对应安全性”的简化版本。代码层只暴露五个接口：`setup`、`extract`、`derive`、`encrypt`、`decrypt`。内部需要明确区分第一层身份矩阵、第二层身份扩展矩阵、陷门委派和离散高斯加密噪声。

推荐的实现顺序是：

1. 先固定一个小参数配置，完成 `TrapGen → Extract → Derive` 的矩阵维度检查。
2. 用全 0/全 1 和短随机消息跑 `Enc → Dec`，单独测量噪声范数。
3. 加入第二层身份后，验证只有 `\rho|snd` 与 `rcv|\phi` 相等时成功。
4. 最后再把 HIBE 消息替换成变长的 `Encode(t)||m`，并设置长度上限。

### 4.5 978 论文增强版

若比赛要求展示 Boyen–Li 的增强隐私，应额外实现匿名 IBE、平均情形提取器 `Ext` 和可复用提取器 `ReExt`。其核心接口是：

```text
Enc(ek_σ, rcv, m):
    r ← {0,1}^ℓ; K1 ← {0,1}^s; K2 ← {0,1}^v
    κ1 ← ReExt(K1, σ); κ2 ← Ext(K2, r)
    c0 ← IBE.Enc(rcv, Encode(m) || r)
    c  ← c0 XOR κ1
    u  ← IBS.Sign(sk_σ, H(c || r || K1 || K2))
    s  ← u XOR κ2
    return (c, s, K1, K2)

Dec(dk_ρ, snd, (c,s,K1,K2)):
    κ1' ← ReExt(K1, snd)
    (m',r') ← IBE.Dec(dk_ρ, c XOR κ1')
    u' ← s XOR Ext(K2, r')
    if IBS.Verify(snd, H(c || r' || K1 || K2), u') = 1: return m'
    return ⊥
```

ROM 原型可用域分离的 SHAKE-256 实现：`Ext(K2,r)=SHAKE256("EXT"||K2||r)`，`ReExt(K1,σ)=SHAKE256("REEXT"||K1||Hash(σ))`，并按组件所需长度截断。论文安全证明中的 extractor 假设不能仅凭 SHAKE-256 自动得到；比赛展示中应明确标注“ROM 工程实例”，不要把它写成标准模型证明。

*下一层：说明正确性、安全性和测试应怎样形成证据链。*

---

## 5. 安全性与正确性论证

基线版的正确性只有一条主链：HIBE 的正确性保证匹配身份下能取回 $(t,m)$，IBS 的正确性保证合法签名通过。隐私性由 HIBE 的匿名 IND-CPA 给出：把挑战从 `rcv_0|\phi_0` 换成 `rcv_0|\phi_0` 上的另一条消息，再换到 `rcv_1|\phi_1`，攻击者不能区分。强可认证性由 IBS 的 UF-CMA 给出：如果攻击者提交一个未请求过的有效 IB-ME 密文，解密后的 $t$ 就能转成一个新的 IBS 伪造。

增强版的隐私证明多了四类混合步骤：先用匿名 IBE 把内部密文替换成随机值；再用 `Ext` 把掩码替换成随机串；用 IBS 的一次性掩码切换发送者签名；最后切换 `ReExt` 的发送者身份。这里需要发送者身份分布具有足够的最小熵，原因是攻击者可以主动尝试 `snd`，低熵身份会被猜中。

实际项目中应把“安全证明”和“工程测试”分开。测试可以证明实现没有明显错误，不能把有限次随机实验写成对 LWE/SIS 的安全证明。

*下一层：把这些性质转成可测量的性能指标。*

---

## 6. 实验与效率

建议报告四组数据：

| 组别 | 测量内容 | 目的 |
|---|---|---|
| 正确性 | 匹配解密成功率、非匹配返回 $\bot$ 比例 | 排除算法/编码错误 |
| 尺寸 | `mpk`、`ek`、`dk`、`ct` 字节数 | 体现 IBS 压缩对密文的收益 |
| 时间 | `Setup`、`KeyExt`、`Extract`、`Derive`、`Enc`、`Dec`、`Sign`、`Verify` | 找出瓶颈 |
| 参数 | $n,m,q,s_0,s,s'$、消息长度和身份长度 | 让结果可复现 |

不要一开始追求标准安全级别。先用教学参数验证流程，再用一组明确标注的候选参数做性能曲线。对每个参数组重复至少 100 次，报告中位数和四分位数；矩阵乘法、采样、序列化分别计时。

论文中的尺寸结论可作为方向性检查：改进 IBS 把签名向量从扩展矩阵列宽缩到 $F_{id}$ 的列宽，理论上减少约 $n\cdot d\cdot\lceil\log q\rceil^2$ 比特（具体数值以实现的编码方式为准）。

*下一层：列出实现时必须正视的边界。*

---

## 7. 局限与开放问题

作者明确给出的边界是：增强隐私版需要 `ReExt`、`Ext` 和足够熵的身份分布；ROM 中用哈希函数替代提取器只是工程实例。指导论文第三章的基线版提供原始隐私和强可认证性，不能直接宣称具有 Boyen–Li 的增强隐私。

实现层面的主要风险有三类。第一，HIBE 和 IBS 的离散高斯采样若用错误分布，功能测试可能通过，但论文对应的安全性和参数估计失效。第二，身份、消息、签名的序列化若不带长度和域分隔，会产生可利用的编码歧义。第三，直接使用浮点数计算范数和采样会导致跨平台不一致；应使用固定精度或经过审计的整数/高精度实现。

可以继续研究的方向包括：把矩阵运算改为环格以缩短密文；比较直接 HIBE+IBS 与 Boyen–Li 掩码版的隐私泄露；以及在不依赖 ROM 的情况下实现通用提取器。

*下一层：给出项目中统一使用的术语。*

---

## 8. 术语表

| 中文 | English | 人话解释 |
|---|---|---|
| 身份基加密 | Identity-Based Encryption, IBE | 身份字符串直接充当公钥标识 |
| 分层式身份基加密 | Hierarchical IBE, HIBE | 身份分成层级，可由第一层密钥派生第二层密钥 |
| 身份基签名 | Identity-Based Signature, IBS | 身份字符串对应签名者，权威机构生成签名密钥 |
| 身份基匹配加密 | Identity-Based Matchmaking Encryption, IB-ME | 发送者和接收者都指定身份，双方匹配才解密 |
| 匿名性 | Anonymity | 密文不泄露所用身份 |
| 强可认证性 | Strong authenticity | 未获得发送者密钥不能造出可通过解密验证的密文 |
| LWE | Learning With Errors | 从带小噪声的线性方程中恢复秘密很难 |
| SIS | Short Integer Solution | 找到短的非零向量使矩阵乘积模 $q$ 为零很难 |
| 陷门 | Trapdoor | 允许权威高效生成短原像的秘密结构 |
| 离散高斯采样 | Discrete Gaussian sampling | 按高斯形状从整数格点采样，控制原像长度和噪声 |
| 随机预言机模型 | Random Oracle Model, ROM | 把哈希函数理想化为可查询的随机函数 |
| 可复用随机性提取器 | Reusable extractor | 多次使用同一高熵秘密仍输出近似随机值的工具 |
| 最小熵 | Min-entropy | 由最可能被猜中的取值衡量随机性 |

---

## 附录：工程落地蓝图

推荐的目录结构如下：

```text
ibme/
  core/encoding.py       # 长度前缀、域分隔、规范序列化
  core/hash_oracle.py    # H1/H2/Ext/ReExt 的接口和 SHAKE 实例
  lattice/modmat.py      # Z_q 矩阵与定长编码
  lattice/gaussian.py    # 离散高斯采样与统计测试
  lattice/trapdoor.py    # TrapGen、DelTrap、SamplePre
  hibe/abb10.py          # Agrawal-Boneh-Boyen 两层 HIBE
  ibs/pan_wagner.py      # 改进 SIS-IBS
  ibme/baseline.py       # 第三章 HIBE+IBS
  ibme/enhanced.py       # Boyen–Li Ext/ReExt 版本
  tests/                 # 正确性、篡改、格式和随机性测试
  experiments/           # 尺寸、耗时、参数扫描
```

实现分四个里程碑。M1 只做矩阵、编码和采样；M2 分别完成 HIBE、IBS 的单元测试；M3 组合成基线 IB-ME 并完成匹配/不匹配/篡改演示；M4 再加入增强隐私版和安全游戏模拟。每个里程碑都保存版本化测试向量。

消息较大时使用混合加密：IB-ME 只封装随机数据密钥，文件本体用 AEAD 加密。这样不会让格密文承载超出噪声预算的大消息；若采用这一工程包装，IBS 应签名规范化后的 `rcv || nonce || AEAD-ciphertext` 或其哈希，并在报告中明确这是对原始消息空间的实现封装。



