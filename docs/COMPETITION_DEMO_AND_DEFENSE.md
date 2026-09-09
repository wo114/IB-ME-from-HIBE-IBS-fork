# 全国密码技术竞赛：M3 演示与答辩材料

## 1. 作品名称与 30 秒介绍

**作品名称：** 基于两层格基 HIBE 与 SIS-IBS 的身份基匹配加密参考实现

**30 秒介绍：**

> 我们实现了指导论文第三章的基线 IB-ME。发送者 Alice 可以指定接收者 Bob，并用 IBS 证明消息来自 Alice；Bob 只有在自己的接收者身份和尝试的发送者身份都匹配时，才能解出消息。系统包含两层 HIBE、SIS-IBS、严格编码、密文篡改检测、CLI 演示和可复现测试。当前是教学参数下的基线参考原型，所有参数标记为 `security_claim: none`，不把功能测试冒充安全证明。

## 2. 现场演示策略

建议准备两条路径：

1. **快速联调路径：** 使用 `--mock`，在现场快速展示完整交互和三种失败情况。必须口头说明 mock 是 TEST-ONLY，没有密码学安全性；
2. **真实格后端路径：** 使用 ABB10 HIBE + SIS-IBS，展示真实后端参数、预先生成的基准结果和一次小消息流程。真实后端的加密较慢，建议提前准备状态目录和录屏/日志，现场需要时只运行解密和篡改验证。

不要只演示成功案例。评委最容易通过“不匹配、篡改、伪造和格式错误”看出方案是否真的实现了匹配语义。

## 3. 快速 CLI 演示

以下命令在仓库根目录执行。若未安装为包，先设置 `PYTHONPATH`：

```powershell
$env:PYTHONPATH = "src"
Remove-Item -LiteralPath .\demo-state -Recurse -Force -ErrorAction SilentlyContinue
Set-Content -LiteralPath .\demo-message.bin -Value "IB-ME demo: Alice -> Bob" -NoNewline
```

### 3.1 初始化与签发密钥

```powershell
python -m ibme.cli setup --params education --state .\demo-state --mock
python -m ibme.cli issue-sender-key Alice --state .\demo-state --mock
python -m ibme.cli issue-receiver-key Bob --state .\demo-state --mock
```

预期现象：生成 `mpk.bin`、`msk.bin`、`state.json` 和摘要派生的 sender/receiver 密钥文件；输出明确写出 `TEST-ONLY mock backends` 与 `security_claim: none`。

### 3.2 正确匹配

```powershell
python -m ibme.cli encrypt --sender Alice --receiver Bob --state .\demo-state --in .\demo-message.bin --out .\demo-ct.bin --mock
python -m ibme.cli decrypt --receiver Bob --sender Alice --state .\demo-state --in .\demo-ct.bin --out .\demo-recovered.bin --mock
Get-Content .\demo-recovered.bin
```

预期结果：退出码 0，恢复内容与 `demo-message.bin` 完全一致。

### 3.3 发送者不匹配

```powershell
python -m ibme.cli decrypt --receiver Bob --sender Carol --state .\demo-state --in .\demo-ct.bin --mock
```

预期结果：输出 `BOTTOM`，退出码为非零值。解释：Bob 正确，但 `snd=Carol` 与加密时的 `phi=Alice` 不同。

### 3.4 接收者不匹配

```powershell
python -m ibme.cli issue-receiver-key Carol --state .\demo-state --mock
python -m ibme.cli decrypt --receiver Carol --sender Alice --state .\demo-state --in .\demo-ct.bin --mock
```

预期结果：输出 `BOTTOM`。解释：发送者正确，但 `rho=Carol` 与加密指定的 `rcv=Bob` 不同。

### 3.5 密文篡改

```powershell
$raw = [System.IO.File]::ReadAllBytes('.\demo-ct.bin')
$raw[0] = $raw[0] -bxor 0xff
[System.IO.File]::WriteAllBytes('.\demo-ct-tampered.bin', $raw)
python -m ibme.cli decrypt --receiver Bob --sender Alice --state .\demo-state --in .\demo-ct-tampered.bin --mock
```

预期结果：输出 `BOTTOM`。协议 magic 被破坏，严格解析拒绝密文。

## 4. 真实后端演示

去掉命令中的 `--mock` 即使用 ABB10 HIBE + SIS-IBS：

```powershell
python -m ibme.cli setup --params education --state .\real-state
python -m ibme.cli issue-sender-key Alice --state .\real-state
python -m ibme.cli issue-receiver-key Bob --state .\real-state
python -m ibme.cli encrypt --sender Alice --receiver Bob --state .\real-state --in .\demo-message.bin --out .\real-ct.bin
python -m ibme.cli decrypt --receiver Bob --sender Alice --state .\real-state --in .\real-ct.bin --out .\real-recovered.bin
```

真实后端使用极小教学参数，但 32B 消息基准中 HIBE 加密中位数约 44.4 秒、密文约 4.7MB。现场不应把等待时间解释为安全性；它体现的是当前逐位独立 LWE 参考实现的工程代价。

## 5. 现场展示顺序（建议 5 分钟）

| 时间 | 内容 | 讲解重点 |
|---:|---|---|
| 0:00–0:30 | 作品问题 | 双方身份都匹配才解密 |
| 0:30–1:20 | 架构图 | Core → Lattice → HIBE/IBS → Baseline → CLI |
| 1:20–2:20 | Alice→Bob 成功 | IBS 签名 + HIBE 两层身份绑定 |
| 2:20–3:10 | Carol 失败与篡改失败 | `BOTTOM`、严格解析、验签 |
| 3:10–4:10 | 测试和攻击回归 | 333 passed，历史共享掩码问题已修复 |
| 4:10–5:00 | 安全边界 | 教学参数、基线方案、无安全等级声明、M4 未实现 |

## 6. 答辩高频问题与建议回答

### Q1：为什么要同时使用 HIBE 和 IBS？

HIBE 绑定 `(接收者, 发送者)` 两层身份，决定谁有机会取出候选载荷；IBS 对 `接收者身份和消息` 签名，证明载荷确实由声称的发送者生成。两者分别承担匹配和认证职责。

### Q2：为什么解密要先 Derive，再 Decrypt，再 Verify？

第一层接收者密钥只能派生某个发送者身份的第二层密钥。顺序体现论文构造：先用 `(rho,snd)` 尝试 HIBE，再对取出的签名和消息做 IBS 验证。任何中间失败都统一返回 `BOTTOM`。

### Q3：为什么不能把身份直接放进密文？

明文携带身份会直接破坏匿名性目标。当前实现把身份编码放进 HIBE 的加密明文，密文字节本身不包含身份字段；身份比较在解密后完成。

### Q4：你们如何处理之前的共享掩码问题？

旧结构所有明文位共享同一个 `u·s`，`c1[j]-c1[0]` 会泄漏比特差分。现在每个 bit 使用独立 `s_j/e1_j/e2_j`，并加入差分聚类、已知明文单 bit 定位和 v1 序列化拒绝测试。代价是密文变大、加密变慢。

### Q5：333 个测试通过是否说明安全？

不说明。测试只能说明当前输入范围内的功能、接口和已知攻击回归通过；它不能替代 LWE/SIS/HIBE/IBS 的安全证明，也不能产生 NIST 等级结论。

### Q6：你们实现的是 Boyen–Li 增强隐私吗？

不是。当前是指导论文第三章的基线 HIBE+IBS。Boyen–Li 方案需要匿名 IBE、`Ext`、`ReExt` 和身份熵条件，属于 M4，当前明确未实现。

### Q7：为什么使用 mock？

mock 只用于先验证协议组合的接口、身份匹配和失败语义。它是 TEST-ONLY，不能用于安全实验或生产部署。真实结果使用 ABB10 HIBE + SIS-IBS 后端。

### Q8：为什么密文这么大？

为关闭共享掩码差分泄漏，当前 v2 为每个明文 bit 保存一条完整 LWE 样本。这个实现优先保证结构性正确性和可审查性，牺牲了教学参数下的尺寸和速度；后续优化必须在不改变接口和安全分析边界的前提下进行。

### Q9：大文件能否直接加密？

当前 M3 只支持 HIBE 载荷上限内的短消息。规范中的 AEAD 混合加密包装还没有实现，不能把当前 CLI 描述成大文件加密工具。

### Q10：你们的创新是什么？

创新点应表述为工程实现和审计方法：模块化接口、双后端契约测试、严格序列化、攻击回归和可复现基准。不要声称提出了新的密码学构造。

## 7. 一页式答辩结论

```text
已完成：M1 基础设施、M2 HIBE/IBS、M3 基线 IB-ME + CLI + 基准
核心性质：匹配成功；三种不匹配返回 BOTTOM；篡改和伪造被拒
测试证据：333 passed, 10 skipped；覆盖 343 个收集项
核心修复：逐 bit 独立 LWE 样本，关闭共享掩码差分泄漏
参数口径：极小教学/调试参数，security_claim: none
安全边界：不宣称 NIST 等级、标准模型安全或安全证明
当前范围：基线方案；Boyen–Li Ext/ReExt 增强隐私属于未开始的 M4
```

## 8. 演示前检查清单

- [ ] 运行 `git status --short`，确认没有未提交修改；
- [ ] 预先准备 `--mock` 快速演示和真实后端日志；
- [ ] 确认演示输出包含 `security_claim: none`；
- [ ] 演示成功、发送者不匹配、接收者不匹配、密文篡改四种结果；
- [ ] 准备架构图和算法流程图；
- [ ] 记住当前真实后端密文尺寸和加密耗时；
- [ ] 明确回答“当前没有实现 M4、Ext、ReExt”；
- [ ] 不把测试通过说成密码学安全证明。

