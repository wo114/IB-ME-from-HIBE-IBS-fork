# 基于两层 HIBE 与 SIS-IBS 的身份基匹配加密

## M3 内部代码审查记录

> 本文件供项目内部审查和协作使用，不作为比赛提交版作品报告。正式作品报告见 [IB-ME作品报告](IBME_作品报告.md)。

**项目状态：M3 基线方案已完成；M4 增强隐私版尚未开始**  
**当前版本：`27f3bd5`**  
**安全口径：教学参数、基线方案、`security_claim: none`**

## 摘要

身份基匹配加密（Identity-Based Matchmaking Encryption，IB-ME）要求发送者和接收者双方的身份同时匹配，接收者才能恢复消息。本项目实现了指导论文第三章所对应的基线构造：两层格基 HIBE 与格基 SIS-IBS 的组合。发送者身份通过 IBS 签名绑定，接收者身份和发送者身份通过两层 HIBE 共同绑定；解密方只有在接收者身份和发送者身份均匹配时，才能通过 HIBE 解密和 IBS 验证。

当前实现包含规范字节编码、SHAKE-256 域分隔哈希、模 $q$ 矩阵与 gadget 工具、离散高斯采样、ABB10 风格两层 HIBE、SIS-IBS、基线协议、CLI、mock 联调后端和可复现基准。M3 全量测试结果为 **333 passed, 10 skipped**。测试覆盖正确性、四种身份组合、篡改、伪造、序列化、身份长度、CLI 和历史共享掩码攻击回归。

本项目是可审查的功能参考原型，不是可部署的密码产品。所有参数均为极小教学/调试参数，未完成 LWE/SIS 安全估计，不能据此宣称 NIST 安全等级、标准模型安全或论文定理已经得到实现验证。Boyen–Li 论文中的 `Ext`、`ReExt` 和增强隐私构造属于 M4，目前没有实现。

**关键词：** 身份基匹配加密；两层 HIBE；SIS-IBS；格密码；可认证加密；教学原型

## 1. 背景与问题

普通 IBE 只判断接收者身份。IB-ME 还要求发送者身份参与匹配：

$$
\rho = rcv \quad\land\quad \phi = snd,
$$

其中：

- $\phi$：真实发送者身份；
- $\rho$：真实接收者身份；
- `rcv`：发送者加密时指定的接收者；
- `snd`：接收者解密时尝试的发送者。

仅把两个身份拼进密文只能实现条件绑定，不能证明密文确实由指定发送者生成。IBS 为 `Encode(rcv) || message` 生成签名，补充来源认证。两层 HIBE 则把 `(rcv, phi)` 作为层级身份，使接收者必须先拥有 `rcv` 的第一层密钥，再针对 `snd` 派生第二层密钥。

本作品的目标不是提出新的密码学假设，而是把论文构造拆成可替换、可测试、可审计的软件模块，并展示一条从格工具到协议组合的完整实现链。

## 2. 总体设计

系统分为五层：

1. **基础设施层**：规范编码、域分隔哈希、随机源、异常和参数对象；
2. **格工具层**：$\mathbb Z_q$ 矩阵、gadget 矩阵、TrapGen、SamplePre、离散高斯；
3. **原语层**：ABB10 风格两层 HIBE 与 SIS-IBS；
4. **协议层**：Baseline IB-ME 组合和 `BOTTOM` 失败哨兵；
5. **应用层**：CLI、状态文件、序列化和基准脚本。

协议层只调用 HIBE/IBS 的公共接口，不读取内部矩阵或私有字段。HIBE 和 IBS 可以使用独立参数，当前真实基准使用 ABB10 HIBE 调试参数与 SIS-IBS 教学参数；mock 后端只用于契约联调。

## 3. 基线算法

### 3.1 Setup

分别运行 HIBE 和 IBS 的 `setup`：

```text
(hpk, hmsk) <- HIBE.Setup(h_params)
(ipk, imsk) <- IBS.Setup(i_params)
mpk = (hpk, ipk)
msk = (hmsk, imsk)
```

### 3.2 发送者密钥与接收者密钥

```text
SKGen(msk, phi): ek_phi <- IBS.KeyExt(imsk, phi)
RKGen(msk, rho): dk_rho <- HIBE.Extract(hmsk, rho)
```

密钥对象保存规范化后的字节身份。`identity_bytes` 是最大字节长度，不是固定长度；HIBE 的身份入口和 mock HIBE 都会强制该上限。

### 3.3 加密

发送者先对接收者身份和消息做规范编码：

$$
u = \operatorname{EncodeMessage}(rcv,m).
$$

然后生成：

$$
t \leftarrow \operatorname{IBS.Sign}(ek_\phi,u).
$$

HIBE 的明文载荷为严格组帧的 `EncodeSignature(t) || EncodeBytes(m)`，加密身份为 `(rcv, phi)`：

$$
ct \leftarrow \operatorname{HIBE.Enc}(hpk,rcv,\phi,\operatorname{payload}).
$$

身份不会以明文身份字段写入密文。

### 3.4 解密

接收者使用自己的第一层密钥和尝试的发送者身份派生：

```text
child_key <- HIBE.Derive(dk_rho, snd)
payload   <- HIBE.Decrypt(child_key, ct)
```

如果 HIBE 解密失败、载荷格式错误、签名重建失败或验签失败，协议统一返回 `BOTTOM`。成功取出载荷后，使用：

$$
\operatorname{IBS.Verify}(ipk,snd,
\operatorname{EncodeMessage}(\rho,m'),t).
$$

验签通过才返回 $m'$。因此四种情况的预期结果是：

| 加密指定接收者 | 解密方接收者 | 尝试发送者 | 结果 |
|---|---|---|---|
| Bob | Bob | Alice（真实发送者） | 返回原消息 |
| Bob | Carol | Alice | `BOTTOM` |
| Bob | Bob | Carol | `BOTTOM` |
| Bob | Carol | Carol | `BOTTOM` |

## 4. 代码审查结论

### 4.1 已通过的审查项

- HIBE 身份顺序始终为 `(parent_id, child_id) = (rcv, phi)`；
- 身份、消息、签名使用长度前缀和域分隔编码；
- 模矩阵、向量和序列化统一检查维度与模数；
- 生产随机源与固定测试随机源分离；
- HIBE 和 IBS 的代数关系在构造或签名阶段自检；
- 协议对象严格拒绝截断、追加、重复字段和错误 magic；
- SenderKey/ReceiverKey 的外层身份与内部绑定身份交叉校验；
- CLI 支持 UTF-8 身份，密钥文件名由身份摘要派生，不把身份原文写入路径；
- mock 后端明确标注 TEST-ONLY，不参与安全声明；
- 历史共享掩码问题已修复：ABB10 密文 v2 为每个明文位单独采样 $(s_j,e_1^{(j)},e_2^{(j)})$，v1 格式明确拒绝；
- 报告、README、参数文件和基准均明确标注 `security_claim: none`。

### 4.2 M3 审查发现并已关闭的问题

早期版本让所有明文位共享同一个 LWE 随机量。攻击者计算 `c1[j] - c1[0]` 可以消去公共掩码，再利用长度前缀中的已知零位恢复明文位。该问题属于结构性密文泄漏，不能靠测试口径解释为“容错”。当前版本改为逐位独立样本，并加入纯密文差分聚类和已知明文单 bit 定位回归测试。

修复带来的工程代价是密文和加密时间按明文 bit 数线性增加。当前 32B 消息的真实后端密文约 4.7MB，加密中位数约 44.4 秒；这组数据只用于展示教学实现的代价，不代表论文级参数性能。

### 4.3 当前未关闭的风险

这些风险不阻断 M3 功能交付，但必须在比赛中主动说明：

1. 参数维度很小，未做 LWE/SIS 安全估计，不能映射到任何安全等级；
2. TrapGen/SamplePre 使用简化采样链，没有完整 MP12 扰动分布；
3. HIBE 身份矩阵和 IBS 哈希是 SHAKE-256 的 ROM 风格工程实例，HIBE 哈希没有绑定 mpk；
4. 离散高斯使用拒绝采样并有截断，采样循环非常数时间；
5. HIBE 本身不是 CCA 完整性方案，基线协议依赖 IBS 做来源认证和身份绑定；
6. 直接 HIBE 载荷有容量上限，当前 M3 尚未实现规范要求的 AEAD 混合加密包装；
7. IBS 的哈希到 $\mathbb Z_q$ 使用取模约简，存在微小统计偏差；
8. Boyen–Li 的 `Ext`、`ReExt`、身份熵条件和增强隐私证明映射尚未实现。

## 5. 测试与实验

### 5.1 测试环境

- Python 3.14.6，CPython；
- Windows 11，AMD64；
- 纯 Python 参考实现；
- 测试随机性使用 `DeterministicRandom`，生产路径默认使用系统 CSPRNG；
- 如需运行 SageMath，按项目规则使用 WSL 环境 `/home/zhang/miniconda3/envs/sage`。

### 5.2 全量结果

执行命令：

```text
python -m pytest -q -p no:cacheprovider --basetemp .pytest-tmp-m4-gate
```

结果：

```text
333 passed, 10 skipped in 628.48s
```

测试收集器显示共 343 项。跳过项是只适用于 ABB10 或特定后端的条件测试，不是失败。

### 5.3 覆盖范围

| 类别 | 覆盖内容 |
|---|---|
| Core/编码 | 长度前缀、域分隔、往返、截断、追加、重复和空身份 |
| 格工具 | 模运算、维度、gadget、离散高斯均值/方差/尾部、TrapGen/SamplePre |
| HIBE | setup、extract、derive、匹配/不匹配、代数关系、篡改、序列化、v1 拒绝 |
| IBS | H1/H2、签名方程、范数界、身份绑定、消息篡改、随机伪造、序列化 |
| Baseline | mock+mock 与 abb10+sis 两种组合、四种身份组合、`BOTTOM`、协议组帧、密文/签名篡改 |
| CLI | 真实后端流程、mock 流程、UTF-8 身份、摘要文件名、状态元数据、参数错误 |
| P0 回归 | 共享掩码差分聚类攻击、已知明文单 bit 定位、v1 密文拒绝 |

### 5.4 基准摘要

基准文件：[experiments/results/baseline-benchmark.md](../experiments/results/baseline-benchmark.md)。真实后端使用 `baseline-hibe-abb10-debug` 与 `ibs-education`，32B 消息、发送者身份 15B、接收者身份 17B。

| 操作 | 中位数 |
|---|---:|
| Setup | 0.090 s |
| IBS KeyExt | 0.155 s |
| HIBE Extract | 0.167 s |
| HIBE Derive | 1.740 s |
| IBS Sign | 0.004 s |
| IBS Verify | 0.001 s |
| HIBE Encrypt | 44.367 s |
| HIBE Decrypt | 2.110 s |

序列化尺寸：`mpk` 5491B、`msk` 9907B、`ek` 7209B、`dk` 80824B、32B 消息密文 4733837B。

## 6. 作品贡献与展示重点

本作品的工程贡献可以概括为：

1. 把论文中的 HIBE、IBS 和 IB-ME 组合拆成稳定的公共接口，支持 mock 与真实格后端替换；
2. 建立从规范编码、矩阵运算、采样、原语到 CLI 的可复现实验链；
3. 把身份顺序、长度限制、序列化和失败语义写成 contract tests；
4. 对共享随机掩码问题进行攻击复现、修复和回归验证；
5. 诚实报告逐位独立修复带来的尺寸与性能代价，并把教学参数与安全声明分离。

这些是实现和审计贡献，不应表述为提出了新的 HIBE、IBS 或安全证明。

## 7. 总结

M3 已经完成指导论文第三章基线方案的功能性实现：匹配身份时能够恢复消息，任一身份不匹配时返回 `BOTTOM`，篡改和随机伪造不能通过协议验证，CLI 和序列化路径可复现。当前版本适合作为全国密码技术竞赛的教学型工程作品和现场演示原型。

作品的安全边界必须保持清楚：当前实现是**教学参数下的基线参考实现**，不是经过参数估计和安全证明的生产方案；它没有实现 Boyen–Li 增强隐私版。后续若进入 M4，应在独立模块中实现 `Ext`、`ReExt`，记录 ROM 和身份熵条件，并重新进行接口、测试和安全口径审查。
