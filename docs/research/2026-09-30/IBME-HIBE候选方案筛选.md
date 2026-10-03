# IB-ME 格基 HIBE 候选方案筛选

> 本文用于为“二层 HIBE + IBS”身份基匹配加密路线筛选 HIBE 组件。排序同时考虑与老师论文通用构造的适配性、匿名性证明、格结构、工程性能潜力、公开实现和截止日期风险。论文声称、公开实现数据和本项目自己的实测分别记录，不能互相替代。

> 检索时间：2026-09-30。检索了老师博士论文、ePrint、DOI/Crossref/OpenAlex 元数据、公开实现和 ETSI 资料。本文是面向本项目的候选筛选，不声称穷尽所有 HIBE 文献，也不把尚未核验的方案写成已实现或已证明安全。

## 1. 先给出综合排序

### 1.1 面向本项目的综合排序

| 排名 | 候选方案 | 适配性 | 性能潜力 | 当前判断 |
|---|---|---:|---:|---|
| 1 | **ABB10 系列 HIBE，主选 [88]** | 高 | 中 | 老师论文直接采用的两层匿名 HIBE 基线，优先作为主线 |
| 2 | **Latte HIBE** | 中 | 高 | 公开实现和性能数据最好，需先补足与匿名 HIBE 要求的对应关系 |
| 3 | **ABB10 系列另一构造 [41]** | 中高 | 中 | 标准模型格基 HIBE 参考方案，可用于和 [88] 比较 |
| 4 | **Zhang–Wu 2017** | 待核验 | 待核验 | 适应性安全格基 HIBE 候选，但匿名性与实现资料尚未闭环 |
| 5 | **Singh–Pandurangan–Banerjee 2012/2014** | 待核验 | 中 | 关注短公钥和标准模型，适合做尺寸参考，不宜直接替换主线 |
| 6 | **Goyal–Koppula–Rajasree 2025** | 理论高、工程低 | 低 | LWE 下适应性匿名 HIBE 的新理论候选，构造复杂，暂不适合竞赛主实现 |

这个排序是综合排序，不是单一性能排名：

- 只看与老师论文的直接适配性，ABB10 [88] 排第一；
- 只看已有工程性能和实现资料，Latte 排第一；
- 只看匿名性和适应性理论方向，2025 年的 Goyal 等方案值得重点阅读，但不适合作为当前工程主线。

当前建议采用“主线 + 性能对比 + 理论储备”的组合：

1. **主线：ABB10 [88] 风格的两层格基 HIBE**；
2. **性能对比：Latte HIBE**；
3. **理论对比：Zhang–Wu 或 2025 年匿名 HIBE 方案**；
4. 只有在匿名性、安全模型、参数和接口全部核对后，才考虑替换 ABB10。

## 2. HIBE 必须满足的项目条件

老师论文第三章的构造 3.3.1 不是任意 HIBE 都能直接接入。其安全定理要求底层 HIBE 至少满足与构造对应的适应性匿名安全性质，论文中使用的是两层匿名 HIBE。

对当前项目，HIBE 候选至少要逐项检查：

1. **层数**：至少支持二层身份 `(rcv | snd)`；
2. **匿名性**：需要核对是否证明了 `Anon-IND-CPA` 或可转换为该性质；普通的身份基 IND-CCA 不能自动等同于身份匿名；
3. **接口**：能够区分 `Setup`、一级 `Extract`、二级 `Derive`、`Enc` 和 `Dec`；
4. **载荷**：能够加密 `签名 t || 消息 m`，而不是只支持极短固定消息；
5. **正确性**：身份匹配、密钥派生、解密失败和噪声界限要能单独证明；
6. **安全模型**：明确标准模型、ROM 或 QROM，并和 IBS 的安全模型及最终 IB-ME 归约保持一致；
7. **参数**：同时满足 LWE/RLWE/NTRU 困难性、陷门采样、解密失败率和载荷容量；
8. **性能**：测量 HIBE 公钥、主私钥、一级密钥、二级密钥、密文、Setup、Extract、Derive、Enc、Dec 和内存占用。

赛题要求至少完成一种基于 LWE/SIS 的完整实例化，并支持组件接口、参数配置和不同实例的尺寸、时间、内存比较。赛题没有把 Ring-SIS、128 位安全、固定速度或某个 HIBE 名称写成额外强制门槛；这些可以作为团队目标，但不能冒充官方硬性要求。

## 3. 候选方案分析

### 3.1 ABB10 [88]：Lattice Basis Delegation in Fixed Dimension and Shorter-Ciphertext HIBE

来源：Agrawal、Boneh、Boyen，CRYPTO 2010。

论文链接：[DOI 10.1007/978-3-642-14623-7_6](https://doi.org/10.1007/978-3-642-14623-7_6)。

#### 方案特点

- 基于格困难问题，核心技术是格基委派；
- 关注固定维度和较短 HIBE 密文；
- 是老师论文第三章选作两层匿名 HIBE 底层的主要参考方案；
- 与当前仓库的 `ABB10HIBE` 后端和二层 HIBE 接口最接近。

#### 适配 IB-ME 的原因

老师论文构造 3.3.1 的调用关系是：

```text
Setup       -> HIBE.Setup + IBS.Setup
RKGen       -> HIBE.Extract(msk, rcv)
Enc         -> IBS.Sign(sender_key, rcv || message)
              HIBE.Enc((rcv || sender), signature || message)
Dec         -> HIBE.Derive(receiver_key, sender)
              HIBE.Dec + IBS.Verify
```

ABB10 [88] 的二层身份和陷门委派结构可以直接对应这组接口，因此它是当前最容易形成“论文构造—代码接口—正确性证明—安全归约”闭环的方案。

#### 优点

- 与老师论文路线直接对应；
- 格基陷门和层级密钥派生结构清楚；
- 适合矩阵 LWE 的完整实例化；
- 当前仓库已有教学/调试后端，便于先冻结协议接口和验证组合逻辑；
- 适合做主线基准，后续更换 HIBE 后端时也能作为对照。

#### 不足和风险

- 矩阵格实现的公钥、密钥和运算开销可能较大；
- 陷门委派、扰动采样和解密噪声需要达到证明级，不能把当前教学采样直接写成论文实现；
- 需要重新核对原始论文的安全游戏、匿名性条件、二层参数和载荷长度；
- 当前仓库后端标注为教学/调试用途，不能把功能测试结果写成 ABB10 已达到正式安全参数。

#### 入选结论

**入选主线。** 它不一定在单项速度上最好，但在老师论文适配性、证明路线和按期完成风险之间最平衡。

### 3.2 Latte HIBE：工程性能候选

来源：Campbell–Groves 的 Latte 方案及 Zhao 等人的实现和优化工作。

来源链接：

- [Quantum-safe HIBE: does it cost a Latte?](https://eprint.iacr.org/2021/222)
- [IEEE TIFS 发表版本 DOI](https://doi.org/10.1109/TIFS.2023.3347880)
- [公开实现 GitLab](https://gitlab.com/raykzhao/latte)
- [ETSI Quantum-Safe Identity-based Encryption 技术报告](https://www.etsi.org/deliver/etsi_tr/103600_103699/103618/01.01.01_60/tr_103618v010101p.pdf)

#### 方案特点

- 使用 NTRU/RLWE 风格的环结构；
- 由 DLP IBE 和 Bonsai Trees HIBE 组合形成；
- 论文给出单层和二层参数集；
- 有完整 C 实现、参数说明和桌面性能评测。

#### 已公开的性能证据

Zhao 等人在论文中报告：

- Latte-3 和 Latte-4 可用于二层 HIBE；
- 优化后的 Delegate 在论文测试平台上约为 0.4 秒和 1.3 秒；
- 私钥长度减少约 2–3 倍；
- 密文尺寸最多减少约 33%；
- 相比 ETSI 实现，加解密速度最高提升约 9.7 倍。

这些数字属于论文特定硬件、编译环境、参数和实现的结果，不能直接当作本项目跑分。论文同时讨论了浮点精度、离散高斯采样、解密失败率和 NTRU/RLWE 攻击成本，这些内容对你们的性能与安全检查很有参考价值。

#### 与本项目的主要问题

Latte 论文重点分析的是 `ID-IND-CCA`、`ID-OW-CPA` 和 ROM 下的 FO 转换，并没有直接给出老师第三章通用构造所要求的 `Anon-IND-CPA` HIBE 证明。因此：

- 不能仅凭 Latte 的 HIBE 名称把它当作匿名 HIBE；
- 不能直接把 Latte 替换进构造 3.3.1 后声称定理 3.3.1 仍然成立；
- 需要确认密文是否隐藏接收者身份、原始论文是否有更强匿名定义，以及能否补出适用归约；
- 若匿名性不能闭环，它仍然可以作为性能基准或独立 HIBE 研究对象，但不是当前 IB-ME 主线的直接替换。

#### 入选结论

**入选性能对比和环结构储备。** 这是目前最有工程价值的外部候选，但在匿名性核验完成前，不列为 IB-ME 主方案。

### 3.3 ABB10 [41]：Efficient Lattice (H)IBE in the Standard Model

来源：Agrawal、Boneh、Boyen，EUROCRYPT 2010。

论文链接：[DOI 10.1007/978-3-642-13190-5_28](https://doi.org/10.1007/978-3-642-13190-5_28)。

#### 优点

- 关注标准模型下的高效格基 IBE/HIBE；
- 与 ABB10 [88] 具有相同研究脉络，适合比较公钥、密钥、密文和委派成本；
- 适合作为老师论文之外的同源理论参考。

#### 不足

- 它不是老师论文构造 3.3.1 直接选定的 [88] 版本；
- 需要重新核对两层支持、匿名性定义和密文载荷容量；
- 公开工程实现和可直接复用的参数资料不如 Latte；
- 不能因为标题含有 HIBE 就自动认为满足 `Anon-IND-CPA`。

#### 入选结论

**入选理论对比基线。** 如果后续发现 [88] 的某一项参数或接口不适合，可优先比较这一本同源构造；在核验前不替换主线。

### 3.4 Zhang–Wu 2017：Adaptively Secure HIBE over Lattice

来源：Leyou Zhang、Qing Wu，2017，Network and System Security。

论文链接：[DOI 10.1007/978-3-319-64701-2_4](https://doi.org/10.1007/978-3-319-64701-2_4)。

#### 入选原因

- 标题和论文主题直接针对适应性安全格基 HIBE；
- 可以作为 ABB10 之外的安全性路线比较；
- 对你们后续检查“选择身份安全”和参数条件有参考价值。

#### 当前缺口

- 目前只核验到正式出版元数据和题名，尚未完成全文算法、匿名性、安全游戏和参数的逐项核对；
- 尚未找到可以直接接入当前仓库的公开实现；
- 不能确认其是否满足老师通用构造要求的匿名 HIBE，而不只是普通自适应 HIBE；
- 不能确认其在 `signature || message` 载荷下的密文和内存表现。

#### 入选结论

**列为待核验理论候选。** 只有在全文确认匿名性、二层接口和参数后，才进入实现筛选。

### 3.5 Singh–Pandurangan–Banerjee：短公钥参数 HIBE

相关来源：

- [Adaptively Secure Efficient Lattice (H)IBE in Standard Model with Short Public Parameters，2012](https://doi.org/10.1007/978-3-642-34416-9_11)
- [Efficient Lattice HIBE in the Standard Model with Shorter Public Parameters，2014](https://doi.org/10.1007/978-3-642-55032-4_56)

#### 入选原因

- 直接关注标准模型、适应性安全和公钥长度；
- 对赛题要求的公私钥尺寸比较有参考价值；
- 可作为 ABB10 公钥尺寸和参数表达的对照。

#### 当前缺口

- 尚未完成全文逐项核验；
- 目前无法确认满足老师要求的匿名性定义；
- 没有与当前 IB-ME 组合、SIS-IBS 签名载荷相匹配的实现数据；
- 不能只凭“短公钥”判断最终 IB-ME 密文或总内存更小。

#### 入选结论

**列为尺寸比较候选。** 适合用于研究报告的横向调研，不宜在队长确定主方案前投入主线实现。

### 3.6 Goyal–Koppula–Rajasree 2025：适应性匿名 HIBE

来源：[A Note on Adaptive Security in Hierarchical Identity-Based Encryption，IACR ePrint 2025/291](https://eprint.iacr.org/2025/291)。

#### 已核验的理论主张

论文声称：

- 在标准模型中从选择性安全 IBE 构造适应性安全 HIBE；
- 在 LWE 等假设下得到适应性安全 HIBE；
- 进一步得到适应性匿名 HIBE；
- 支持无界长度身份和无界递归委派。

#### 工程问题

论文的构造涉及 OTSE、可委派 PRF、混淆电路等复杂组件；匿名扩展还涉及 lockable obfuscation。论文给出的密文和密钥是多项式开销表达，没有提供适合当前竞赛原型的轻量参数和现成实现。

#### 入选结论

**作为理论前沿储备，不作为当前实现候选。** 它适合支撑你们在报告中说明“适应性匿名 HIBE 的理论发展”，不能直接变成竞赛系统的高性能组件。

### 3.7 Bonsai Trees：底层技术参考，不作为独立候选

Bonsai Trees 通过格基委派支撑 HIBE，是许多格基 HIBE 方案的基础技术。它更适合作为陷门委派和层级密钥派生的理论背景，不应与完整 HIBE 方案混为一谈。

相关来源：[Bonsai Trees, or How to Delegate a Lattice Basis](https://eprint.iacr.org/2009/359)。

## 4. 横向比较

| 候选 | 主要结构/假设 | 匿名性 | 自适应安全 | 二层适配 | 公开实现 | 性能证据 | 当前用途 |
|---|---|---|---|---|---|---|---|
| ABB10 [88] | 矩阵格、LWE/格陷门委派 | 老师论文将其作为匿名 HIBE 使用，原文仍需按定义核验 | 需按原论文和老师论文核对 | 高 | 当前仓库有教学后端 | 需自行测量 | 主线基线 |
| Latte | NTRU/RLWE、环结构 | 当前核验材料未给出老师要求的匿名证明 | 有 ROM 下安全分析 | 高 | 有公开 C 实现 | 强 | 性能对比 |
| ABB10 [41] | 标准模型格基 IBE/HIBE | 待核验 | 待核验 | 待核验 | 未找到直接可用实现 | 理论描述 | 同源理论基线 |
| Zhang–Wu | 格基 HIBE | 待核验 | 主题是适应性安全 | 待核验 | 未找到直接可用实现 | 未核验 | 理论候选 |
| Singh 等 | 格基 HIBE、短公钥 | 待核验 | 主题是适应性安全 | 待核验 | 未找到直接可用实现 | 尺寸方向 | 公钥比较 |
| Goyal 等 2025 | LWE、OTSE/PRF/混淆电路 | 明确声称适应性匿名 HIBE | 明确声称 | 支持无界层级 | 未见工程实现 | 理论开销大 | 理论储备 |

## 5. 对 IB-ME 的性能测量要求

不能只测 HIBE 的 `Encrypt` 和 `Decrypt`。最终比较要同时保留 HIBE 单体数据和 IB-ME 组合数据。

### HIBE 单体

- `Setup` 时间；
- `Extract` 时间；
- `Derive` 时间；
- `Encrypt` 时间；
- `Decrypt` 时间；
- 主公钥和主私钥尺寸；
- 一级密钥和二级密钥尺寸；
- HIBE 密文尺寸；
- 峰值内存；
- 解密失败率和批量正确性结果。

### HIBE + IBS 组合

- IB-ME 公钥和主私钥尺寸；
- 发送者加密密钥和接收者解密密钥尺寸；
- IBS 签名尺寸；
- 最终 IB-ME 密文尺寸；
- `SKGen`、`RKGen`、`Enc`、`Dec` 总时间；
- 合法身份、错误发送者、错误接收者、篡改密文和伪造密文的行为；
- 内存占用和消息长度变化。

### 公平性控制

固定 CPU、内存、操作系统、编译器或解释器、库版本、线程数、优化选项、参数集、身份长度、消息长度、重复次数和随机种子。若使用 NTT、SIMD 或其他加速，应单独记录启用和未启用两组结果。硬件加速条件必须写入评测表，不能把不同硬件上的数字直接横向比较。

## 6. 当前仓库适配结论

当前仓库的协议层已经将 HIBE 和 IBS 分成可替换接口，因此从软件架构上可以接入多个 HIBE 后端。但“接口可替换”不等于“方案安全性质相同”。

当前 ABB10 后端仍属于教学/调试实现，相关结论必须保持以下边界：

- `security_claim: none`；
- 当前参数不能代表最终安全参数；
- 简化的 TrapGen、委派和采样不能代替证明级算法；
- 当前功能测试不能代替 LWE、HIBE 或最终 IB-ME 安全证明；
- 当前 HIBE 载荷容量必须先确认足以容纳 SIS-IBS 签名和消息；
- 任何换成 Latte、Zhang–Wu 或其他 HIBE 的尝试，都要重新核验正确性、匿名性、安全模型、参数和实现证据。

## 7. 给队长的直接决策建议

队长当前不需要一次性实现所有 HIBE，先确定以下路线即可：

| 决策项 | 建议 |
|---|---|
| 主 HIBE | 先冻结 ABB10 [88] 风格两层 HIBE，完成论文构造对应的基线闭环 |
| 性能候选 | 读取并复现实测 Latte，作为环结构和性能对照 |
| 理论候选 | 继续核验 Zhang–Wu；如需前沿理论背景，引用 2025 年匿名 HIBE 工作 |
| HIBE 替换条件 | 必须同时满足二层、匿名性、载荷容量、正确性、安全模型和参数约束 |
| 主线切换时机 | 等候选方案完成全文核验和小规模公平跑分后再决定 |

推荐的项目路线是：

1. 用 ABB10 HIBE + 当前 SIS-IBS 完成基线正确性和协议级测试；
2. 在相同 IB-ME 接口下测量 ABB10 的尺寸、时间和内存；
3. 研究 Latte 的接口适配和匿名性缺口，先作为独立性能对照；
4. 如果 Latte 无法满足匿名性，保留其性能结果，不把它写成最终 IB-ME 安全方案；
5. 队长确定最终 HIBE 后，再冻结你的正确性、安全性和性能证明范围。

## 8. 研究状态边界

下列内容目前是候选或待核验状态：

- ABB10 [88] 的具体参数实例尚未完成最终安全校准；
- Latte 尚未完成匿名性与当前 IB-ME 定理的适配证明；
- Zhang–Wu 和 Singh 等方案尚未完成全文级算法和安全模型核验；
- 2025 年匿名 HIBE 尚未完成工程可行性评估；
- 没有任何候选因为公开论文性能数字而自动满足赛题 A01—A15。

最终报告必须分别列出：正确性证明、HIBE/IBS 正式安全归约、参数安全估计、实现测试和性能测量。失败攻击测试或功能测试只能说明当前实现范围内的证据，不能替代一般安全证明。

## 参考来源

- 老师博士论文：第三章第 3.3 节、第 3.4 节和第 3.5 节；
- Agrawal、Boneh、Boyen：[Lattice Basis Delegation in Fixed Dimension and Shorter-Ciphertext Hierarchical IBE](https://doi.org/10.1007/978-3-642-14623-7_6)；
- Agrawal、Boneh、Boyen：[Efficient Lattice (H)IBE in the Standard Model](https://doi.org/10.1007/978-3-642-13190-5_28)；
- Zhao 等：[Quantum-safe HIBE: does it cost a Latte?](https://eprint.iacr.org/2021/222)；
- Zhang、Wu：[Adaptively Secure Hierarchical Identity-Based Encryption over Lattice](https://doi.org/10.1007/978-3-319-64701-2_4)；
- Singh、Pandurangan、Banerjee：[Short Public Parameters 2012](https://doi.org/10.1007/978-3-642-34416-9_11) 与 [Shorter Public Parameters 2014](https://doi.org/10.1007/978-3-642-55032-4_56)；
- Goyal、Koppula、Rajasree：[A Note on Adaptive Security in Hierarchical Identity-Based Encryption](https://eprint.iacr.org/2025/291)；
- Cash、Hofheinz、Kiltz、Peikert：[Bonsai Trees, or How to Delegate a Lattice Basis](https://eprint.iacr.org/2009/359)；
- 官方赛题验收基准：`outputs/IBME-赛题验收基准/2026-09-27/赛题验收基准.md`。
