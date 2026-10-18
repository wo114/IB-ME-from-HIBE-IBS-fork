# 竞赛演示与答辩脚本

**作品名称：** 基于多类格困难假设的抗量子身份基匹配加密通用设计和优化实现<br>
**材料事实版本：** `IBME-SAME-VERSION-MATERIALS/1`<br>
**参数卡 SHA-256：** `970c5303f5d8a7e73cbbfaee8dd50a3c3186f83b5c40062a32a68c4d682edcd6`<br>
**当前主演示：** `latte3-bnn-mldsa44-hybrid-byteauth`<br>
**Suite digest：** `10a23d28bfdf9b2e18b140149561c43d62f2649feb78b72510d350b419233346`

本稿与[作品报告](IBME_作品报告.md)、[主展示参数卡](deliveries/2026-10-18-main-showcase-cards/README.md)和公开收据使用同一组事实。当前演示底座是 **LATTE-3 + BNN/ML-DSA-44 + Hybrid + BYTEAUTH**，`allow_mock=false`。图形界面尚未交付，最终三组代表尚未锁定；因此现场以真实 CLI、公开收据和只读证据校验为主。

## 1. 一句话介绍

> 发送者 Alice 指定接收者 Bob，Bob 解密时还要声明期望发送者 Alice；只有接收者和发送者两个身份都匹配，系统才返回消息。我们把两层格 HIBE、格 IBS、混合加密、完整字节认证和可恢复状态做成一个可替换、可预检、可审计的通用框架。

必须紧接着说明：当前配置是研究实现，`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`；功能和性能结果不能替代安全证明。

## 2. 演示前的真实性闸门

现场第一步不是直接 Setup，而是运行所选 Suite 的静态预检。先根据当前电脑实际环境选择能够导入项目依赖的 Python/Sage 解释器，记为 `<sage-python>`；普通证据脚本使用 `<python>`。不要复制仓库历史材料或另一台电脑中的 Sage 绝对路径。

```sh
<sage-python> -m ibme.cli check \
  --hibe latte --hibe-params seed32 \
  --ibs cert-ml-dsa --ibs-params ml-dsa-44 \
  --transport hybrid --protocol byteauth-v1 \
  --signature-format reference --json
```

只有同时满足以下条件才进入现场真实新建流程：

- `compatibility.ok` 为 `true`；
- HIBE 和 IBS 的 `runtime_available` 均为 `true`；
- Suite digest 为 `10a23d28bfdf9b2e18b140149561c43d62f2649feb78b72510d350b419233346`；
- 输出仍是 `security_claim=none`，没有自动更换后端或参数。

当前这台电脑在 2026-10-18 的实际预检以退出码 2 拒绝，原因是：

```text
hibe: LATTE requires its explicit built WSL native bridge; no fallback
ML-DSA native engine missing; build in WSL, no fallback
execution=not_executed
```

这表示当前机器缺少两个原生引擎，不是一次算法运行失败。引擎未准备好时，不执行 Setup，不换用其它算法冒充主演示；转入第 5 节的固定收据重放，并播放同一 Suite 的已归档真实流程录屏（如已准备）。

## 3. 原生依赖就绪时的真实 CLI 流程

以下命令均从仓库根执行。提前设置项目实际需要的 `PYTHONPATH` 或完成 editable 安装；命令中的 `<sage-python>` 始终替换为当前电脑实际可用的解释器。

### 3.1 准备固定边界的 32 B 消息

```sh
<python> -c "from pathlib import Path; Path('demo-message.bin').write_bytes(b'IBME demo payload'.ljust(32, b'.'))"
```

讲解词：原始收据使用 64 B 接收者身份、64 B 发送者身份和 32 B 消息。现场用短文本身份便于观看，但参数卡里的计时和尺寸只属于原始固定边界，不能把现场不同身份长度的输出混入那组统计。

### 3.2 建立冻结的主组合

使用全新的 `demo-state` 目录：

```sh
<sage-python> -m ibme.cli setup \
  --state demo-state \
  --hibe latte --hibe-params seed32 \
  --ibs cert-ml-dsa --ibs-params ml-dsa-44 \
  --transport hybrid --protocol byteauth-v1 \
  --signature-format reference
```

预期输出应明确显示：

```text
hibe=latte
ibs=cert-ml-dsa
transport=hybrid
protocol=byteauth-v1
signature_format=reference
state version=2
security_claim: none; backend_admitted: false; parameters_are_formal: false
```

再核对冻结状态：

```sh
<python> -m json.tool demo-state/state.json
```

`state.json` 保存完整 Suite 和摘要；后续命令从该状态恢复选择，不能通过命令行静默改换后端或格式。

### 3.3 发放发送者和两个接收者密钥

LATTE 当前参数最多容纳 2 个接收者、每个接收者 2 个子身份。Bob 用于正确解密，Carol 用于接收者错配；不要再临时增加第三个接收者。

```sh
<sage-python> -m ibme.cli issue-sender-key Alice --state demo-state
<sage-python> -m ibme.cli issue-receiver-key Bob --state demo-state
<sage-python> -m ibme.cli issue-receiver-key Carol --state demo-state
```

讲解词：Alice 的发送密钥来自 IBS，Bob/Carol 的接收密钥来自 HIBE 第一层。文件名由身份 UTF-8 字节摘要派生，私钥对象还绑定 Suite 和公钥上下文。

### 3.4 双身份匹配成功

```sh
<sage-python> -m ibme.cli encrypt \
  --state demo-state --sender Alice --receiver Bob \
  --in demo-message.bin --out demo-ct.bin

<sage-python> -m ibme.cli decrypt \
  --state demo-state --sender Alice --receiver Bob \
  --in demo-ct.bin --out demo-recovered.bin

<python> -c "from pathlib import Path; assert Path('demo-message.bin').read_bytes() == Path('demo-recovered.bin').read_bytes(); print('MATCH: recovered bytes equal input')"
```

预期：解密退出码 0，恢复的 32 B 与输入逐字节一致。

### 3.5 三种身份错配均拒绝

下列三条命令预期打印 `BOTTOM` 并以退出码 1 结束；它们是预期失败，不是演示脚本故障。

```sh
# 只有发送者声明错误：Bob 的密钥，声称发送者 Carol
<sage-python> -m ibme.cli decrypt \
  --state demo-state --sender Carol --receiver Bob \
  --in demo-ct.bin --out wrong-sender.bin

# 只有接收者错误：Carol 的密钥，仍声称发送者 Alice
<sage-python> -m ibme.cli decrypt \
  --state demo-state --sender Alice --receiver Carol \
  --in demo-ct.bin --out wrong-receiver.bin

# 两者都错误：Carol 的密钥，声称发送者 Carol
<sage-python> -m ibme.cli decrypt \
  --state demo-state --sender Carol --receiver Carol \
  --in demo-ct.bin --out both-wrong.bin
```

讲解词：接收者错会在 HIBE 身份路径上失败；发送者错会改变第二层派生和最终 IBS 身份验证。对外都返回统一的 `BOTTOM`，不泄露内部失败阶段。

### 3.6 完整密文字节篡改拒绝

复制密文并翻转中间一位：

```sh
<python> -c "from pathlib import Path; p=Path('demo-ct.bin'); b=bytearray(p.read_bytes()); b[len(b)//2] ^= 1; Path('demo-ct-tampered.bin').write_bytes(b)"

<sage-python> -m ibme.cli decrypt \
  --state demo-state --sender Alice --receiver Bob \
  --in demo-ct-tampered.bin --out tampered-output.bin
```

预期：打印 `BOTTOM`，退出码 1，不产生有效明文。BYTEAUTH 验证完整外层密文字节，Hybrid 又把完整 HIBE capsule 放入 AEAD AAD；这仍是条件式实现论证和有限测试，不是 CCA 安全证明。

### 3.7 新进程恢复

关闭当前终端，再打开一个终端、重新选择同一 `<sage-python>`，只运行：

```sh
<sage-python> -m ibme.cli decrypt \
  --state demo-state --sender Alice --receiver Bob \
  --in demo-ct.bin --out demo-recovered-after-restart.bin

<python> -c "from pathlib import Path; assert Path('demo-message.bin').read_bytes() == Path('demo-recovered-after-restart.bin').read_bytes(); print('RESTORE: recovered bytes equal input')"
```

每条 CLI 本身就是一个新 Python 进程。这个步骤强调 Suite、公开对象和接收状态能够从磁盘恢复；它不重新 Setup 或发钥。归档基准中的 3 个恢复进程共完成 9 次恢复后解密，恢复读取 0 B 公共随机源。

## 4. 演示时应展示的主组合数字

归档实验使用 3 套独立系统状态，每套 3 对 warm 加解密；身份各 64 B、消息 32 B。下面是主组合公开观察值：

| 指标 | 结果 |
|---|---:|
| Setup 中位数（3） | 0.984492 s |
| 发送钥中位数（3） | 0.273598 s |
| 接收钥中位数（3） | 0.754343 s |
| cold Encrypt 中位数（3） | 0.224485 s |
| 首次 Decrypt 中位数（3） | 0.403997 s |
| warm Encrypt 中位数（9） | 0.211125 s |
| warm Decrypt 中位数（9） | 0.280116 s |
| 恢复对象中位数（3） | 0.665062 s |
| 恢复后 Decrypt 中位数（9） | 0.281654 s |
| 完整外层密文（12） | 142051—142146 B |
| 10 ms 进程树 RSS 最大观察 | 480243712 B |

环境为 Core Ultra 9 275HX、WSL2 Linux 6.18.33.2、Python 3.13.14、Sage 10.9、OMP 4、OpenBLAS 1。该表来自固定公开收据，不是当前缺依赖电脑的现场测量。样本量小，warm 共享各自状态，RSS 可能重复计算共享页或漏过短峰。

## 5. 原生依赖未就绪时的证据重放

证据重放不是算法执行，必须把两者分开说。选择当前电脑实际可用的普通 Python 3 解释器，运行：

```sh
<python> docs/research/2026-10-18-full-system-luo/evidence/compare.py
<python> docs/deliveries/2026-10-18-main-showcase-cards/evidence/verify.py
<python> docs/deliveries/2026-10-18-same-version-materials/evidence/verify.py
```

三个脚本依次核对统一比较数据、参数卡和报告/答辩事实，不导入密码后端、不生成密钥、不读取私有状态。它们会核对原始收据 SHA-256、Suite、输入、重复次数、恢复、计时、尺寸、源码版本和安全标志。

主演示原始收据：

```text
docs/research/2026-10-18-full-system-baseline/evidence/latte-mldsa44.json
SHA-256 dc8e5cef04534df6cd643a6c4aa908cb7b74e5e27c27e6730becadbe038ef8ab
```

另外两组同边界对照：

| 对照 | warm Encrypt / Decrypt | 完整密文 |
|---|---:|---:|
| LATTE-3 + BNN/Falcon-512 | 0.200346 / 0.249274 s | 138150—138207 B |
| LATTE-3 + Luo module compact | 0.364461 / 0.229220 s | 151876—151955 B |

强调：三组共享同一 LATTE HIBE，且安全目标未证明等价。它们展示不同 IBS 工程取舍，不构成“同安全等级速度榜”。

## 6. 五分钟讲解顺序

| 时间 | 展示内容 | 必须说清的事实 |
|---:|---|---|
| 0:00—0:35 | 应用问题 | 接收者与发送者双身份都要匹配 |
| 0:35—1:15 | 通用架构 | Wang 基线；HIBE/IBS 独立；Hybrid 与 BYTEAUTH 的位置 |
| 1:15—1:45 | 主组合和参数 | LATTE N=1024、q=68718428161；BNN/ML-DSA-44；固定 Suite digest |
| 1:45—2:10 | 真实性预检 | 原生依赖缺失会明确拒绝且无回退；当前机器如实进入证据重放 |
| 2:10—3:20 | 功能 | 匹配成功、三种错配、篡改和新进程恢复 |
| 3:20—4:10 | 结果 | 0.211125/0.280116 s、142051—142146 B、重复次数与环境 |
| 4:10—4:40 | 多算法取舍 | Falcon 紧凑、Luo 原生模格；不是三种 HIBE，不跨安全目标排名 |
| 4:40—5:00 | 边界 | none/false/false，GUI 和最终三代表尚未完成，测试不是证明 |

## 7. 高频答辩问题

### Q1：为什么要同时使用 HIBE 和 IBS？

HIBE 把接收者和发送者放入两层解密路径，IBS 认证发送者并绑定接收者与消息。只把身份写成普通密文字段不能同时实现双身份匹配与来源认证。

### Q2：为什么 HIBE 顺序必须是 `(rcv, phi)`？

接收者先获得以 `rcv` 为第一层身份的长期接收密钥，解密时再按期望发送者 `phi` 派生第二层密钥。这与 Wang 构造和项目公共契约一致，所有后端必须保持同一顺序。

### Q3：为什么使用 Hybrid？

BNN/ML-DSA 完整签名和协议载荷远大于 LATTE 的 32 B seed 模式。Hybrid 让 HIBE 只加密随机 seed，再由 HKDF 和 AES-256-GCM 承载完整数据，同时把 suite、公钥上下文和完整 capsule 纳入 AAD。它是容量与工程适配，不自动升级底层安全模型。

### Q4：BYTEAUTH 解决什么？

它认证完整外层密文字节，并把一次性公钥承诺签入内部 IBS，用于拒绝 wire 任意受保护区域的修改。它不修复一个本来可伪造的 IBS，也不直接证明 CCA 或 QROM 安全。

### Q5：为什么选择 ML-DSA-44 作主演示？

它的基础规范、固定源码和 210 个原语向量最易解释和复现，现有完整收据也最完整。这个选择降低展示风险，不表示完整 BNN IBS 或 IB-ME 已获得 FIPS/NIST 认证。

### Q6：Falcon 看起来更小、更快，为什么不直接宣布它最好？

现有 Falcon 和 ML-DSA 卡没有建立相同具体安全目标。可以比较同一实测边界下的尺寸和时间，但不能据此声称“同安全等级更优”；而且当前实现是 Falcon v1.2 padded-512，不是 FN-DSA/FIPS 206。

### Q7：三张参数卡是否代表三种 HIBE？

不是。三组都使用 LATTE-3，只替换 IBS。最终三组代表要在两种在途 HIBE 交付、完成真实配对和参数核对后再锁定。

### Q8：当前电脑为什么不能现场新建？

静态预检发现 LATTE bridge 和 ML-DSA native engine 尚未构建，因此在任何密钥或随机数生成前拒绝。这是依赖状态，不是算法失败。我们展示固定收据和哈希核验，不使用回退实现伪造现场结果。

### Q9：恢复 0 B 公共随机源是什么意思？

归档恢复进程从已保存的公开对象和接收状态恢复并解密，没有重新取公共随机数，且这些对象字节保持不变。它证明固定状态恢复路径按当前实现工作，不证明防回滚、硬断电安全或分布式事务。

### Q10：这些测试能否证明抗量子安全？

不能。测试验证功能、接口、已知攻击样例和运行观察；安全性还依赖困难假设、论文模型、参数映射和组合条件。当前元数据明确是 none/false/false。

### Q11：作品的原创性在哪里？

贡献是可替换原语的统一实例化、跨层规范绑定、完整字节认证、持久状态事务、真实组合验收、固定源码与可审计测量。Wang 构造、LATTE、BNN、ML-DSA、Falcon 和 Luo 算法分别引用原来源，不把复用算法宣称为原创。

## 8. 现场检查清单

- [ ] 冻结演示提交、cards.json 和三份原始收据的 SHA-256；
- [ ] 在实际演示电脑重新运行主 Suite 预检并保存完整输出；
- [ ] 只有预检成功时才新建真实状态；预检失败则明确使用收据重放；
- [ ] 新状态目录不含旧密钥、pending 标记或私人演示数据；
- [ ] 成功、三种错配、篡改和恢复命令均已排练，并区分退出码 0/1/2；
- [ ] 录屏与现场命令使用同一 Suite digest，不混入其它参数；
- [ ] 参数卡、报告、PPT、讲稿的时间、尺寸、次数和环境一致；
- [ ] 不展示主私钥、接收私钥、随机种子或未清理的状态目录；
- [ ] 口头明确 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`；
- [ ] 明确图形界面尚未交付、最终三组代表尚未锁定。
