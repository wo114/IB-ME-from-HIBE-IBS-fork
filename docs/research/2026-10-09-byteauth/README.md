# 原安全目标修复：完整密文字节认证与剩余 IBS 根因

日期：2026-10-09；基点 `1307cee`。用户指出旧漏洞长期未修复，主 AI 调整排序：可独立完成的密文字节认证先实现，不等 HIBE/IBS 新后端全部交付。**默认 CLI 的原 c1 低位篡改目标已通过无 XFAIL 回归；公开伪造与发送者冒名仍未修复。** 当前教育参数及整体系统 `security_claim: none`。

## 1. 为什么不能把三个问题一直捆在一起等

LEGACY-IBS-01 的公开线性签名伪造，直接导致 LEGACY-IBME-01 的发送者冒名，两者是同一条不安全 IBS 根因链。简单调小验签界、增加身份检查或屏蔽某个攻击向量不能替代合法原语/参数，可能破坏诚实签名。本轮仍使用真实公开求解器，无 sender-key 查询，保留这两项严格 XFAIL。

LEGACY-CT-01 的原因另有一条链：CPA 格加密允许小误差修改后恢复同一消息；IBS 对明文验签，未覆盖外层格密文字节。原来把其实现也放在新后端之后，是工作排序错误。现在增加独立包装并切换默认入口，原 BaselineIBME 留作数学参考/负面对照；没有宣称修好了底层 CPA 原语。

## 2. 计算顺序与绑定

1. 每次 Encrypt 用系统 CSPRNG 新生成一把一次性 OTS 私钥及公钥 vk。
2. 封装 `IBME:BOUND-MSG:v1 || LP(commit(vk)) || LP(application_message)`，作为原 Wang 基线的消息。
3. 原基线照常对接收者和该消息签 IBS，再在 `(receiver,sender)` 下 HIBE 加密。接收者身份、发送者身份均未移到公开头部。
4. OTS 对外层版本、公钥上下文承诺、完整 vk 和完整基线密文字节签名。
5. 解密先验证完整外层 OTS，再用原基线解密并验 IBS，最后检查内层 vk 承诺等于外层 vk。任意数据失败返回 BOTTOM。

这是原构造外的工程版本；原 HIBE/IBS 接口与长期密钥格式不改。先写入 [IMPLEMENTATION_SPEC §6](../../../IMPLEMENTATION_SPEC.md)，再实现。既不出现“先签完整密文但签名又在被签密文中”的循环，也不用公开 checksum 或接收者可重算的 MAC 冒充发送者认证。

### 条件式论证与原文引用

[Lamport 一次性签名原文](https://lamport.azurewebsites.net/pubs/dig-sig.pdf)的单次使用、原像与第二原像条件用于组织 OTS 理论依据。本实现采用常见的逐摘要 bit 双原像 Lamport 型格式，SHAKE-256 的元素像、消息摘要和公钥承诺分别域分隔；要求相应原像/第二原像及消息/承诺碰撞安全，未给具体 NIST 或 QROM 等级。签名私钥对象第二次使用会报错；密钥不写入主状态，Python 内存释放不等于保证安全擦除。

攻击者可以持有接收者密钥并看到原明文与 IBS 签名：

- 沿用原 vk 却修改签过的完整字节或外层签名，需违反强一次性不可伪造性（摘要碰撞、未揭示原像恢复，或已揭示原像的第二原像）。
- 换新 vk 后可以自己生成有效 OTS，但内层 IBS 已绑定原 vk 承诺；除承诺碰撞外，成功需伪造 IBS 对新消息 envelope 的签名。
- 完全相同的密文字节重放属于应用层重放问题，不当作篡改拒绝目标。

[CHK 原文](https://eprint.iacr.org/2003/122.pdf)说明强一次性签名和验证密钥绑定的重要性，但其构造把 vk 作为 IBE 身份；本版本未这么做，**不引用 CHK 定理宣称 CCA**。上面是本工程包装的条件式认证论证，不重做 HIBE/IBS 基础安全证明。取消 Boyen–Li 增强隐私的范围决定不变。

由于当前 IBS 可以公开伪造，第二个分支实际可被攻击。测试专门用新 vk、公开伪造 IBS 和公开 HIBE 加密构造完整合法外层，确认冒名消息仍被接受。这是保留的真实反例，不能把 OTS 包装单独称为完整安全 IBME。

## 3. 新格式与真实开销

`IBME:BYTEAUTH-CT:v1 || LP(public_context) || LP(ots_public_key) || LP(inner_ciphertext) || LP(ots_signature)`；严格拒绝错误版本、截断、追加、重复字段和超限长度。context、承诺均 64 B；内部密文≤64 MiB。所有 hash 继续使用不同角色域的 SHAKE-256，旧六个冻结域不改。

OTS：512 个摘要 bit，每 bit 两个 64 B 随机原像；公钥像体 65536 B，签名 32768 B，外层完整 framing 比原 inner 多 **98421 B**。内层 envelope 另增加 **89 B**，会增加按位 HIBE 载荷及成本。它是方便审查的未压缩正确性基线，未宣称性能优化或密码学原创；后续压缩/更高效已有 OTS 另作同目标对照。

CLI education 的 HIBE 仅把容量 400 B 扩为 489 B，并改用明确的 BYTEAUTH 调试参数名；n、m、q、采样宽度与 IBS 教育参数未升级安全等级。原 400 B 小容量 state 可能容不下新 envelope；在新目录 setup 新状态，或者仅用显式 `--legacy-baseline` 研究旧密文，不能靠自动回退接收未认证格式。没有自动改写用户现有 state/密钥文件。

实际教育参数：HIBE n=8、m=168、q=524288、s₀=3、s=1、s′=1、身份上限 32 B、载荷上限 489 B；IBS n=8、m=80、q=257、s₀=4、s=10、s′=64。IBS 参数元数据仍写 identity_bytes=8/max_message_bytes=32，旧 IBS 的独立入口以调用方和 HIBE 容量约束为准，不能把这个元数据当作新执行的 32 B 检查。

公开伪造为何是结构性问题也可以直接算出：F 的列数为 80+8·9=152，理论验签平方界为 64²·152=622592（代码用浮点近似）；满行秩的公开 F 可选 8 个枢轴列解非零目标，居中后各系数≤128，平方范数最多 8·128²=131072，已经落在验签界内。零目标也可加一个自由坐标构造非零核向量，平方界最多 131073。这个参数区间允许公开短原像，不能通过筛掉某一个攻击样本修好。替换 IBS 及合法选参是剩余两项目标的必要工作。

## 4. 攻击验收

| 目标/对照 | 当前结果 |
|---|---|
| 原公开线性 IBS 伪造拒绝 | 未修复，严格 XFAIL |
| 原未发 sender-key 的冒名拒绝 | 未修复，严格 XFAIL |
| c1 最后一系数低位 XOR 1 | 默认 BYTEAUTH 返回 BOTTOM，无标记通过 |
| 同一修改在未认证 inner 上解密 | 仍恢复同一 envelope，明确负面对照 |
| 持接收者密钥：换 vk 并重签修改后的完整 ciphertext | OTS 有效，但内层 vk 承诺不匹配，返回 BOTTOM |
| 不取 sender-key：公开伪造 IBS、自己生成 vk 与外层签名 | 仍被接受，明确不安全根因对照 |
| 上下文、vk、inner、OTS 签名字段修改 | 拒绝 |
| 三种身份错配、截断/追加/重复/未知版本 | 拒绝 |
| 新入口收到旧未认证格式 | 拒绝；只有显式 legacy 研究开关允许访问 |

原低位回归没有改成破坏 magic 的容易用例：先确认 honest 解密成功、旧 inner 仍规范加载且 c1 只改一个低位、未认证 inner 的明文完全不变，再检查带原 OTS 的新版本拒绝。接收者重签测试进一步通过公开 OTS 验证后才执行目标断言。数据准备失败会报错，不能算修复通过。

## 5. 验证与剩余工作

Windows Intel Core Ultra 9 275HX / Python 3.14.6 / pytest 9.1.1：安全目标与新版本批次 **28 passed、2 xfailed**。WSL2 指定 Sage 环境 Python 3.13.14 / pytest 9.1.1：同批次 **28 passed、2 xfailed**。24 项新测试覆盖 OTS 单次使用、公开验签、固定长度、字段/上下文绑定、身份匹配、接收者新 vk 重签和 CLI 不自动降级。消息包含空串、二进制、UTF-8、256 B；真实原低位反例使用 1 B 消息与 Alice/Bob 身份，测试随机流固定，仅用于重放。

完整 Baseline/CLI、编码与新版本回归 **175 passed**，包含默认真实 ABB10/SIS CLI 和 mock 的完整流程。两个未修复目标在 `--runxfail` 下实测 **2 failed**，均为攻击已经通过验签或解出冒名消息的目标断言；不是新的非预期功能失败。批次有重叠，不相加。测试不能替代 HIBE、IBS、哈希原语或包装的一般安全证明；不发布教学参数安全等级。

与 CI 相同的基础/Core/格工具/Luo/攻击/新版本选择批次本地实测 **396 passed、2 xfailed**，已把新版本测试和状态解释接入 CI。

```text
python -B -m pytest -p no:cacheprovider -ra --tb=short tests/test_known_security_gaps.py tests/test_byteauth.py --junitxml=test-results/byteauth-targets.xml
python -B -m pytest -p no:cacheprovider -ra --tb=short tests/test_baseline_ibme.py tests/test_encoding.py tests/test_byteauth.py --junitxml=test-results/byteauth-protocol.xml
python -B -m pytest -p no:cacheprovider --runxfail -ra --tb=short tests/test_known_security_gaps.py::test_public_linear_forgery_is_rejected tests/test_known_security_gaps.py::test_sender_impersonation_is_rejected --junitxml=test-results/byteauth-unfixed-strict.xml
wsl --cd /mnt/d/zcode_projects/ibme bash -lc '~/miniconda3/envs/sage/bin/python -B -m pytest -p no:cacheprovider -ra --tb=short tests/test_known_security_gaps.py tests/test_byteauth.py --junitxml=test-results/byteauth-wsl.xml'
```

工作排序改为：当前先交付字节认证；下一项完成选定 Luo 模格的数学组件与真实 IBS、合法参数/引用对应，随后用不带 XFAIL 的相同公开伪造与冒名目标验收替换后端，再接队友 HIBE。不能让证明/参数调研无限替代实现和攻击验收。

修改跨 Core、协议和 CLI 的原因是 OTS 原语、内外绑定和默认入口必须同时实现；协议只走后端公共接口，没有读取 HIBE/IBS 私有矩阵或密钥。文件：`src/ibme/core/lamport_ots.py`、`src/ibme/protocol/byteauth.py`、`src/ibme/protocol/__init__.py`、`src/ibme/cli.py`、`tests/test_byteauth.py`、`tests/test_known_security_gaps.py`、CI、IMPLEMENTATION_SPEC、README、KNOWN_SECURITY_GAPS、PROJECT_RESTART、主 AI 任务书及本报告。全部修改提交并同步远端。
