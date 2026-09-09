# 基于两层格基 HIBE 与 SIS-IBS 的身份基匹配加密

## 作品报告（M1–M3）

### 摘要

身份基匹配加密（Identity-Based Matchmaking Encryption，IB-ME）要求发送者和接收者的身份同时满足匹配条件，接收者才能恢复消息。本作品实现了基于两层格基 HIBE 和 SIS-IBS 的基线 IB-ME 方案：发送者使用身份基签名绑定接收者身份与消息，两层 HIBE 将接收者身份和发送者身份共同绑定到密文，解密方只有在两个身份均匹配时才能完成解密和验证。

作品完整实现了 M1–M3 的基础设施、格工具、密码原语和基线协议：包括规范字节编码、域分隔哈希、模 $q$ 矩阵与 gadget 工具、离散高斯采样、两层 HIBE、SIS-IBS、基线协议、命令行工具和可复现实验。系统支持二进制消息、UTF-8 身份、严格序列化和多种异常输入处理。全量功能测试结果为 **333 passed, 10 skipped**。

本作品定位为教学参数下的基线参考实现。所有参数均标记为 `security_claim: none`，未进行 LWE/SIS 安全估计，不对应任何 NIST 安全等级。Boyen–Li 方案中的 `Ext`、`ReExt` 和增强隐私构造不属于本次 M3 作品范围。

**关键词：** 身份基匹配加密；两层 HIBE；SIS-IBS；格密码；身份认证；教学参考实现

### 一、研究背景

普通身份基加密只判断接收者身份。身份基匹配加密进一步要求发送者指定发送对象，接收者也要声明发送者身份，匹配条件为：

$$
\rho = rcv \quad\land\quad \phi = snd.
$$

其中 $\phi$ 是真实发送者身份，$\rho$ 是真实接收者身份，`rcv` 是发送者加密时指定的接收者，`snd` 是接收者解密时尝试的发送者。

仅把两个身份作为普通字段写入密文，不能同时完成身份匹配和来源认证。本作品采用两层 HIBE 处理身份层级，采用 SIS-IBS 对规范化的接收者身份和消息进行签名，从而形成“身份匹配 + 来源认证”的组合结构。

### 二、作品目标

1. 实现指导论文第三章所对应的两层 HIBE + IBS 基线构造；
2. 为编码、格运算、陷门采样、HIBE 和 IBS 建立可替换的模块接口；
3. 实现匹配成功、身份不匹配和非法输入下的确定性协议行为；
4. 提供命令行演示、规范序列化和可复现实验数据；
5. 明确区分功能原型、教学参数和密码学安全结论。

### 三、M1–M3 完成范围

| 阶段 | 完成内容 | 在本作品中的作用 |
|---|---|---|
| M1 基础设施 | 规范编码、SHAKE-256 域分隔哈希、随机源、异常类型、模 $q$ 矩阵、gadget、离散高斯和陷门工具 | 为所有上层算法提供统一的数据、随机性和格运算接口 |
| M2 密码原语 | 两层 ABB10 风格 HIBE、SIS-IBS、TEST-ONLY mock 后端及各自契约测试 | 分别实现身份层级绑定和发送者来源认证 |
| M3 协议与应用 | Baseline IB-ME、严格协议序列化、CLI、双后端联调、篡改/伪造测试和性能基准 | 将 M1/M2 组合成可运行、可演示、可复现的完整作品 |

本报告覆盖以上三个阶段。M4 Boyen–Li 增强隐私版属于后续研究内容，不计入本次作品实现范围。

### 四、总体方案

系统由基础设施、格工具、原语、协议和应用五层组成。

```text
应用层：CLI / Demo / Benchmark
        ↓
协议层：Baseline IB-ME
        ↓
原语层：两层 HIBE + SIS-IBS
        ↓
格工具层：Zq 矩阵、gadget、TrapGen、SamplePre、离散高斯
        ↓
基础设施层：规范编码、SHAKE-256、随机源、参数与异常
```

HIBE 与 IBS 通过公共接口组合，协议层不读取底层矩阵或私有密钥字段。测试时可以用 mock 后端验证协议接口；真实实验使用 ABB10 风格 HIBE 和 SIS-IBS 后端。

### 五、算法设计

#### 1. 初始化

分别运行 HIBE 和 IBS 的初始化算法：

```text
(hpk, hmsk) ← HIBE.Setup(h_params)
(ipk, imsk) ← IBS.Setup(i_params)
mpk = (hpk, ipk)
msk = (hmsk, imsk)
```

两个组件可以使用独立参数，参数快照会随密钥序列化保存。

#### 2. 密钥生成

```text
ek_phi ← IBS.KeyExt(imsk, phi)
dk_rho ← HIBE.Extract(hmsk, rho)
```

`ek_phi` 是绑定发送者身份的签名密钥，`dk_rho` 是绑定接收者身份的 HIBE 第一层密钥。

#### 3. 加密

发送者先计算：

$$
u=\operatorname{EncodeMessage}(rcv,m),
\qquad
t=\operatorname{IBS.Sign}(ek_\phi,u).
$$

随后构造载荷：

```text
payload = DOMAIN_SIGNATURE
          || EncodeBytes(t.to_bytes())
          || EncodeBytes(m)
```

最后在 HIBE 身份对 `(rcv, phi)` 下加密：

$$
ct=\operatorname{HIBE.Enc}(hpk,rcv,\phi,payload).
$$

身份和消息使用长度前缀与域分隔编码，身份原文不作为明文身份字段直接出现在密文中。

#### 4. 解密

接收者使用自己的第一层密钥和声明的发送者身份：

```text
child_key ← HIBE.Derive(dk_rho, snd)
payload   ← HIBE.Decrypt(child_key, ct)
```

解出载荷后，解析签名和消息，并验证：

$$
\operatorname{IBS.Verify}
(ipk,snd,\operatorname{EncodeMessage}(\rho,m'),t)=1.
$$

当 HIBE 解密、载荷解析、签名重建或验签任一步失败时，协议返回 `BOTTOM`；成功时返回消息 $m'$。

#### 5. 两层 HIBE 的格基实例

HIBE 使用：

$$
A=[\bar A\mid G-\bar A R_A].
$$

第一层身份矩阵和第二层身份对矩阵分别满足：

$$
A R_1+G=H(\rho),
$$

$$
B_\rho R_2+G=H(\rho,\phi),
\quad B_\rho=[A\mid H(\rho)].
$$

当前密文采用逐明文位独立的 Regev 样本。对第 $j$ 位独立采样 $s_j$、$e_1^{(j)}$ 和 $e_2^{(j)}$：

$$
c_2^{(j)}=B_{rcv,\phi}^{T}s_j+e_2^{(j)},
$$

$$
c_{1,j}=u^Ts_j+e_1^{(j)}+b_j\lfloor q/2\rfloor.
$$

解密方用第二层陷门生成 $B_{\rho,snd}x=u$ 的短原像，通过 $q/4$ 阈值恢复明文位，再检查密文中的身份绑定信息。

#### 6. SIS-IBS 实例

身份扩展矩阵满足：

$$
H_1(mpk,id)=A\widehat R_{id}+G,
\qquad F_{id}=[A\mid H_1(mpk,id)].
$$

对：

$$
h_2=H_2(mpk,id,message),
$$

签名算法生成短向量 $z$，满足：

$$
F_{id}z=h_2\pmod q.
$$

验证检查 $z\ne0$、等式成立和范数界满足要求。

### 六、软件实现

- 语言：Python 3，纯 Python 参考实现；
- 模块目录：`src/ibme/core`、`lattice`、`hibe`、`ibs`、`protocol`；
- 应用工具：`src/ibme/cli.py`；
- 参数记录：`params/`；
- 基准结果：`experiments/results/`；
- 测试目录：`tests/`。

规范编码使用 `uint32 big-endian` 长度前缀。所有模 $q$ 系数统一表示为 `[0,q)`。生产路径默认使用系统随机源，测试路径使用可注入的固定随机源，以保证测试可重复。

CLI 支持 `setup`、`issue-sender-key`、`issue-receiver-key`、`encrypt` 和 `decrypt`。身份可以是可打印 UTF-8 字符串，进入密码算法前统一转换为字节；密钥文件名由身份 UTF-8 字节的 SHA-256 摘要派生。

### 七、测试与实验结果

测试环境为 Windows 11、AMD64、Python 3.14.6、CPython。全量测试命令为：

```text
python -m pytest -q -p no:cacheprovider --basetemp .pytest-tmp-m4-gate
```

测试结果：

```text
333 passed, 10 skipped in 628.48s
```

测试覆盖以下场景：

| 测试方向 | 内容 |
|---|---|
| 正确性 | 匹配身份下恢复空消息、二进制消息和普通文本 |
| 匹配语义 | 接收者不匹配、发送者不匹配、双方均不匹配 |
| 格工具 | 模运算、矩阵维度、gadget、离散高斯、TrapGen/SamplePre |
| HIBE | 两层委派、代数关系、身份绑定、密文结构与序列化 |
| IBS | 签名方程、范数界、消息篡改和随机伪造 |
| 协议格式 | 截断、追加、重复字段、错误 magic 和非法载荷 |
| CLI | 真实后端、mock 后端、UTF-8 身份和错误退出码 |

真实后端基准使用 32B 消息、发送者身份 15B、接收者身份 17B：

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

对应序列化尺寸为：`mpk` 5491B、`msk` 9907B、`ek` 7209B、`dk` 80824B、密文 4733837B。

### 八、安全边界与使用声明

本作品必须按以下口径理解：

1. 当前实现是**教学参数下的基线方案参考实现**；
2. 所有参数的 `security_claim` 均为 `none`，没有任何安全等级结论；
3. 当前结果验证的是功能、接口、编码和已知输入场景，不替代 LWE、SIS、HIBE、IBS 或 IB-ME 安全证明；
4. TrapGen/SamplePre 使用简化采样链，输出分布未达到证明级要求；
5. SHAKE-256 身份哈希是 ROM 风格工程实例，不是标准模型构造；
6. HIBE 层不提供完整 CCA 安全，协议通过 IBS 做来源认证和消息绑定；
7. 当前直接 HIBE 载荷有消息长度上限，尚未提供 AEAD 大文件混合加密；
8. Boyen–Li 增强隐私方案的匿名 IBE、`Ext`、`ReExt` 和身份熵条件尚未实现。

因此，本作品适合用于密码技术竞赛中的算法流程展示、接口设计、功能实验和工程审计教学，不适合生产部署或承载真实秘密数据。

### 九、作品特色

1. 使用分层接口组合 HIBE 与 IBS，便于替换原语后端；
2. 将身份顺序、编码格式、长度上限和失败语义写入统一规范；
3. 同时提供真实格后端与 TEST-ONLY mock 后端，便于分层验证；
4. 支持二进制消息和 UTF-8 身份的命令行流程；
5. 提供可复现测试和尺寸、耗时基准；
6. 在作品展示中明确区分教学参数、基线方案和增强隐私方案。

### 十、总结

本作品完成了两层格基 HIBE 与 SIS-IBS 基线 IB-ME 的软件化实现。系统实现了发送者身份、接收者身份和消息之间的绑定，完成了匹配解密、身份不匹配处理、签名验证、严格序列化和命令行演示，并通过了完整功能测试。

当前版本的价值在于提供一套结构清晰、可运行、可复现、边界明确的教学参考实现。后续工作可以在独立的 M4 模块中研究 Boyen–Li 的增强隐私构造，但必须重新记录 ROM 假设、身份熵条件、参数来源和安全证明范围。
