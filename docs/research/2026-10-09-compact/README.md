# M2-B4：Luo 模格签名的规范无损压缩与完整密文尺寸

日期：2026-10-09；基点 `8459f77`。开工时 origin/main 与本地一致，没有新提交或待合并 PR；上一轮 GitHub CI（run 37938130913）已成功。本轮只处理签名传输格式、显式研究配置和差分验收，不改四算法、参数、哈希输入或队友 HIBE/采样文件。

**已实现 `MODULE-COMPACT/1`：真实签名从 29455 B 降至 16063 B，减少 13392 B（45.466%）。完整 BYTEAUTH 密文减少相同字节数，仅缩小约 0.518%–0.519%。** 数学系数、两个 Verify 哈希的完整域/输入及公开验签结果一致；不是新算法实例，也未取得新的安全等级。

研究数据见 [Windows 结果](compact-native.json)、[WSL Sage 环境结果](compact-sage.json)和[仅含公开数据的两种签名向量](public-vectors.json)。两个环境的参数、签名/哈希摘要、全部六个完整密文摘要、OTS 公钥摘要及规范化源码指纹一致。JSON 文件换行按 LF 归档；比较的是 JSON 值及实际二进制向量，不把操作系统换行差异当密码差异。

## 1. 参数和安全口径

原参数保持：N=256，(k,l)=(11,10)，q=274877844481，NTT 根153250464611，η=1，κ=64，γ₁=125440，γ₂=31470387200，γ₃=15270991360，d=28；β₁=64，β₂=8028160。来源仍是 [M2-B1](../2026-10-09-m2b/README.md) 的研究输入和 [M2-B3](../2026-10-09-admission/README.md) 的条件/成本筛查；没有照搬作者 Table 1 的安全位数。

身份≤64 B，IBS 输入≤4096 B，应用消息≤3924 B；Extract/Sign 各1024次、单整数抽样128次、身份缓存最多64个。降低传输长度不会提高 IBS 输入上限。HIBE 继续使用已有 ABB10 教学配置：n=8、m=168、q=524288、s₀=3、s=s′=1，底层身份86 B、种子32 B，完整 DEM 载荷上限65536 B。全部17项 IBS 参数和 HIBE 配置记录在结果 JSON。

安全声明始终 `security_claim: none`、`backend_admitted: false`、准入安全组合数0。本实现为可变时序研究代码，继承经典 ROM 哈希解释；无新的 QROM、CCA、普通隐私或完整不可伪造证明。原文定理和固定缓存的模拟条件仍以 [M2-B3](../2026-10-09-admission/README.md) 为准。位打包不补这些条件，也不修复默认 education 的公开 IBS 伪造/冒名根因。

## 2. 编码为何无损

`src/ibme/ibs/luo_module_codec.py` 在冻结的 `LuoModuleSignature` 数学对象外增加编码器、解码器和适配器。所有向量按多项式行序、系数下标递增，以最高位优先连续打包；不足一个字节的末尾低位必须为零。

| 字段 | 参考格式 | 压缩格式 | 当前字段字节数：参考 → 压缩 |
|---|---|---|---:|
| z | 有符号64位系数 | z+Zmax，36位；Zmax=γ₂−β₂−1=31462359039 | 20480 → 11520 |
| c | N个有符号字节 | N位存在位图，再按非零位置递增存κ个符号位；1为−1、0为+1 | 256 → 40 |
| w₁ | 每系数16位 | 每系数11位，保留1024最高进位 | 5632 → 3872 |
| h | 每系数1字节 | 全部 kN 个二进制位；不额外限制重量 | 2816 → 352 |
| framing、参数、上下文 | 六个字段、REF版本 | 七个字段、COMPACT版本 | 271 → 279 |
| 合计 | MODULE-REF/1 | MODULE-COMPACT/1 | **29455 → 16063** |

z 的合法区间到 `[0,2Zmax]` 是一一映射，没有模 q 化、截断或舍入。位宽可容纳整个区间，剩余码点必须拒绝。w₁ 可取1024，不能误用10位；端点测试也保留全部 Hint 位。c 的存在位图必须恰有κ个1，符号数量固定，位置顺序固定，故正负挑战可唯一重建。每个定长位流加零填充有唯一编码。

于是对每个合法数学签名 σ，有 `decode(encode(σ),pk)=σ`；对每个被接受的规范字节串 b，有 `encode(decode(b,pk))=b`。这里的“合法”指对象的维度、范围、权重和上下文符合契约，不等于通过密码学 Verify。

编码没有改变 H1/H2：Verify 仍使用原 64位系数哈希输入编码和原域。差分直接截取两次 Verify 的完整 `(domain, encoded_input)` 并比较，不只比较两个签名都能通过。同随机流的两套后端还核对相同 Setup/Extract 结果、缓存快照、数学签名、抽样次数及随机字节消费。

原四算法所在 `luo_module.py` 和数学文件未修改。`LuoModuleCompactIBSBackend` 继承它们，Sign 只包装输出，Verify 解开包装后调用同一公开方程；为继承的 Sign 内部诚实检查，也接受原数学对象。**wire 加载器严格只接收自己选定的格式**，不会尝试另一解码器。

## 3. 严格解析和兼容

规范定义已加入 [IMPLEMENTATION_SPEC.md](../../../IMPLEMENTATION_SPEC.md)。wire 为：

```text
L24C1 || LP(IBME/LUO2024/MODULE-COMPACT/1) || LP(SIGNATURE)
      || LP(params) || LP(context) || LP(z) || LP(c_presence)
      || LP(c_signs) || LP(w1) || LP(h)
```

params136 B、context64 B。总输入限制1 MiB；长度、系数数量和宽度由已验证公钥推导，先逐字节核对嵌入参数/上下文，再解包。每个系数流最多4096个；不会按密文自报维度进行无界分配。

截断、追加、重复/缺少字段、magic/version/kind 异常、参数/上下文错配、字段长度错误、位图重量错误、非零尾填充、未使用 z/w₁ 码点均拒绝。独立 bit-string oracle 与生产流式打包器比较；N=2 的编码样例专门覆盖尾位。小样例仅用于解析检查，不声称 authentic 或安全。

新状态显式选择：

```text
python -m ibme.cli setup --params luo-module-research --signature-format compact --state compact-state
```

`state.json` 保存 `signature_format`；后续签发/加解密只从状态读取，旧 reference 状态继续可读，v1 缺少该字段时按已知 reference 格式处理。reference 仍是默认选项，education/mock 不允许 compact。未知值、错误类型或不适用的配置报参数错误；不自动探测 magic 后回退，不修改既有密钥格式或固定身份缓存。

两种格式的密文应使用各自状态/研究 runtime。不要把改写 state 当已有密文的迁移：外层 OTS 认证整包，改签名字节会改变 HIBE/DEM/外层签名；不得为了对照而让同一 Lamport 私钥签两个不同包。

## 4. 完整组合的实际收益

同一真实研究组合、参数、公钥/长期密钥、Alice（5 B）、Bob（3 B）、应用输入和格式边界，分别实际完成 Encrypt、序列化、Decrypt 与外层 OTS 检查。每种格式/输入运行1次，共6个完整往返，另有6个身份不匹配拒绝。两种世界使用独立随机流，共6个不同 OTS 公钥；没有用一把一次性密钥重签两份对照密文。

| 应用消息 | reference 完整密文 | compact 完整密文 | 节省 | 整包降幅 |
|---:|---:|---:|---:|---:|
| 0 B | 2580256 B | 2566864 B | 13392 B | 0.519018% |
| 32 B | 2580288 B | 2566896 B | 13392 B | 0.519012% |
| 3924 B | 2584180 B | 2570788 B | 13392 B | 0.518230% |

HIBE 胶囊两边均为2452065 B，签名节省完整传递到 DEM 和整包，其余结构尺寸不变。位压缩的效果属格式优化，**不是组合本身 A+B<C 的证据**。本轮没有测性能加速；主要空间成本仍在 HIBE 胶囊。不能把45.466%的签名降幅写成整包降幅，也不能从更少字节直接推出 Encrypt/Decrypt 更快。

## 5. 验收、环境和复现

Windows11（build26200），Intel Core Ultra9 275HX，Python3.14.6、pytest9.1.1、cryptography49.0.0；WSL 使用指定 conda 的 Sage10.9/Python3.13.14、同版本 pytest/cryptography，实际 OpenSSL 等记录在各结果。另用打包运行时 Python3.12.14/cryptography50.0.2构建并安装 wheel 到隔离目录，仅给公钥和两种签名做新进程验签；确认加载已安装包、严格双解码器和 compact runtime 选择。

| 批次 | Windows | 指定 WSL Sage 环境 |
|---|---:|---:|
| 新 codec：bit oracle、端点、解析、完整哈希差分、四算法/随机消费、公开新进程 | 75 passed | 75 passed |
| 新 compact 完整组合、有效类型伪造/接收者重签、CLI/缓存/元数据 | 21 passed | 21 passed（包含于下行46项） |
| 既有 hybrid HIBE + 参考研究组合 | 67 passed | 本轮仅其中参考组合25项（包含于下行） |
| 参考研究组合 + compact 组合 | compact21 + reference25（分别在两批中） | 46 passed |
| 完整当前 basic CI 选择 | 559 passed、2 xfailed | 本轮未全量复跑 |
| 原 Baseline/默认 CLI/UTF-8 身份与状态回归 | 69 passed | 本轮未复跑 |

两个 XFAIL 仍是旧 education 的真实公开伪造和冒名，不能算安全通过；新 compact 测试没有 XFAIL。规范新格式的公开猜测能被正确解码，再因公开方程失败而拒绝；接收者重签攻击的外层 OTS 可验证，随后绑定/IBS拒绝。攻击检查没有靠旧格式类型不兼容凑数。功能测试和有限攻击样本均不能替代证明。

从仓库根目录复现（Windows PowerShell）：

```powershell
python -m pytest -p no:cacheprovider -q tests/test_luo_module_codec.py tests/test_luo_compact_ibme.py
python -m pytest -p no:cacheprovider -q tests/test_hybrid_hibe.py tests/test_luo_hybrid_ibme.py
python -m pytest -p no:cacheprovider -q tests/test_baseline_ibme.py
$env:PYTHONPATH='src'
python -B experiments/research/luo_compact_audit.py --output test-results/compact-native.json --vectors-output test-results/compact-public-vectors.json
python -B experiments/research/verify_luo_compact_vectors.py docs/research/2026-10-09-compact/public-vectors.json
```

basic CI 的561个收集项及准确选择命令见 `.github/workflows/basic-checks.yml`。WSL：

```text
wsl -- bash -lc "cd /mnt/d/zcode_projects/ibme && ~/miniconda3/envs/sage/bin/python -B -m pytest -p no:cacheprovider -q tests/test_luo_module_codec.py"
wsl -- bash -lc "cd /mnt/d/zcode_projects/ibme && ~/miniconda3/envs/sage/bin/python -B -m pytest -p no:cacheprovider -q tests/test_luo_compact_ibme.py tests/test_luo_hybrid_ibme.py"
wsl -- bash -lc "cd /mnt/d/zcode_projects/ibme && PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -B experiments/research/luo_compact_audit.py --output test-results/compact-sage.json"
```

源码指纹按 LF 规范化保存，生成结果可核对实际参数与公共摘要。验证 wheel：`python -m pip wheel . --no-deps --wheel-dir test-results/compact-wheel`，`python -m pip install --no-deps --target test-results/compact-installed test-results/compact-wheel/ibme-0.1.0-py3-none-any.whl`，随后将 `PYTHONPATH` 指向安装目录，在独立目录运行 `experiments/research/verify_luo_compact_vectors.py` 的绝对路径并给出公开向量文件绝对路径；无需主私钥或发送密钥。本轮使用3.12.14打包运行时完成这些命令，主测试仍使用3.14.6。

首个审计命令未设置 src 路径而报 ImportError，设置 PYTHONPATH 后完整执行成功；隔离检查最初比较原始 JSON 文件换行而失败，改为比较 JSON/二进制数据后通过。两项均非密码算法或测试断言的最终失败。

## 6. 文件范围、WIP 和下一项

我方跨 IBS/协议/CLI/验收边界修改的原因：新增 codec 必须经冻结公开接口进入真实 payload，且配置应跨进程保存；没有读取队友新后端的私有矩阵、密钥或改变其语义。修改列表：

- `src/ibme/ibs/luo_module_codec.py`、`src/ibme/ibs/__init__.py`：编码和公开适配器；
- `src/ibme/protocol/luo_hybrid.py`、`src/ibme/cli.py`：显式选择/元数据和既有状态兼容；
- `tests/test_luo_module_codec.py`、`tests/test_luo_compact_ibme.py`：两层差分和攻击回归；
- `experiments/research/luo_compact_audit.py`、`verify_luo_compact_vectors.py`：独立位流对照、实际整包尺寸和公开向量读取；
- `.github/workflows/basic-checks.yml`、`IMPLEMENTATION_SPEC.md`、README、工作记录、已知缺口及主 AI 工作单：规范、CI和交付边界；
- 本目录报告、两环境结果及公开向量：冻结证据。

WIP：CHKP/可信 HIBE 和完整安全组合尚未准入；Luo 的原文模拟/缓存条件、正式发布参数及实现模型继续保留；education 两个认证反例未关闭。没有新增多算法/多假设完整安全实例，没有发布生产参数、QROM证明或组合创新结论。

**下一轮主 AI 做完整系统冷/热基线和资源账本**：同一研究参数、输入和安全目标，对 reference/compact 建立相同 Setup/发钥/Encrypt/Decrypt/序列化计时边界；区分首次准备、可复用上下文、采样重试与内存，给后续联合优化确定可测瓶颈。真实优化先实测单项及完整消融，再判断 A+B<C；不扩大证明任务。队友继续 CHKP 两层匿名 HIBE 和采样交接，外部身份≤64 B、底层固定编码86 B及32 B种子要求保持。
