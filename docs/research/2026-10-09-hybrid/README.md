# 大载荷 HIBE 适配与 Luo 模格 IBS 真实组合

日期：2026-10-09；基点 `2297a9f`。远端无新增提交、无待合并 PR。主 AI 本轮范围：协议侧 HIBE 大载荷适配、研究 CLI、完整组合测试与攻击对照；不修改队友 CHKP/格工具，不改变 Wang 签名输入及 BYTEAUTH 绑定。实现及参数声明仍为 `security_claim: none`、`backend_admitted: false`。

## 实施前冻结的设计及条件依据

本轮将混合加密放在 HIBE 的载荷接口后面。完整签名/消息仍是 Wang 的 HIBE 载荷，由 HIBE 在 (rcv,phi) 的规范编码下加密新随机 32 B 种子，再通过 HKDF-SHA256 与 AES-256-GCM 加密完整载荷。每次加密有新种子及 12 B nonce；完整胶囊字节、公钥上下文、suite、nonce、长度参与 AAD。身份或可枚举身份摘要不出现在新外层头部。种子/DEM 密钥只在内存中使用。

依据：Shoup 的 [KEM/DEM 框架](https://www.shoup.net/papers/iso-2_1.pdf)、[RFC 5869](https://www.rfc-editor.org/info/rfc5869/)、[AESGCM 官方接口](https://cryptography.io/en/49.0.0/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM)。本版本是 HIBE 加密均匀种子的载荷扩展，未自称标准 HPKE 套件，也未引用 CCA KEM 定理给 CPA HIBE 直接授予 CCA 安全。

条件映射：先用底层 HIBE 的消息隐私将胶囊中的种子替换为独立种子，DEM 仍用原种子；KDF 只依赖种子和公开固定上下文，不依赖身份或胶囊，模拟者可计算含胶囊的 AAD。再以均匀种子上的 KDF 密钥隐匿条件及 DEM 的单次消息隐私替换消息。身份隐匿另依赖底层匿名 HIBE，可在消息相同、长度相同的条件下切换胶囊身份并计算 AAD/DEM。需要核验的游戏/密钥查询限制沿用 Wang 对匿名 HIBE 的要求；上述只是经典条件对应，不是当前教学 HIBE 或整个系统的安全证明。

持钥接收者可恢复种子并重算 AEAD，因此新适配器自身不承担发送者认证。BYTEAUTH 保持外层强 OTS 和内层 IBS 对 OTS 公钥承诺的绑定。修改原认证密文而保留 vk，需要 OTS 伪造；换新 vk 重签又需修改 IBS 签入的承诺。接收者已知密钥的 MAC 不代替这两层。[RFC 9180 §9.1.1](https://www.rfc-editor.org/rfc/rfc9180.html#section-9.1.1)也明确讨论了持有接收密钥后重加密的身份冒充风险；其 HPKE 定理不是本方案的直接定理。

旧原始 HIBE 的 c1 低位修改可能恢复同一个短种子；AAD 对原始胶囊逐字节绑定，必须在新包装中拒绝该修改，同时保留底层容错反例作为负面对照。仍接受相同字节密文的重放，本轮不实现重放状态。

研究入口为 `--params luo-module-research`，显式保留 none；底层 ABB10 教学参数不充当正式安全 HIBE，模块 IBS 采用 M2-B2 真实研究输入。默认 education 继续保留两个旧认证目标，不能把原标记移除后称全部修复。研究配置的合法新格式要单独进行公开签名猜测、冒名和接收者重签测试，不依赖旧签名类型不兼容来拒绝。

## 1. 已完成的真实组合

新增 `hybrid_hibe.py` 的六个 HIBE 方法及五类对象。它包装底层公开 API，不修改原 HIBE 矩阵、陷门、采样或算法文件。底层只接收 32 B 种子，原先至少 29563 B 的 Wang/BYTEAUTH 载荷完整进入 DEM；没有将 IBS 改成签种子、略去签名或只签应用哈希。

`luo_hybrid.py` 提供独立的真实研究组合及明确参数/资源解码器；加密前检查应用上限，模块 IBS 参数和包装资源与配置不一致的状态拒绝。CLI 通过 state 的明确 profile 恢复相应对象，不隐式降级。新 profile 禁用 mock、旧未认证开关及对已存在密钥的 setup 覆盖。

新增两个状态修正：Luo 发钥后把固定身份缓存原子写回 msk，使不同 CLI 进程重复给同一身份发钥仍得到同一份密钥；研究 state 加载检查公钥/主状态公开上下文一致。元数据重复字段、错误类型和矛盾 profile 拒绝。密钥快照是明文，原子写回是单写者设计，没有实现并发锁或加密私钥仓库。

这是一套**真实组件的功能组合**，包括实际格运算、模格签名、AEAD 和 OTS；没有把 mock 组合算真实实例。HIBE 是原有 ABB10 风格的教学实现；正式的 CHKP 两层原语由队友继续实现。本组合的拟依赖分别为矩阵 LWE（HIBE 研究方向）和 MLWE/MSIS（Luo §4）；另有 AES、HKDF、SHAKE 和 OTS 的条件，不能把混合包装计为新格假设或密码学原创。安全获准完整组合仍为 0。

## 2. 发现并修复的身份长度泄漏

初步接线发现：旧 HIBE 将身份长度反映到逐比特密文数量，只检查“密文不包含身份原字节”不足以验收匿名性。因此本轮补充固定宽度单射编码：

```text
IDPAD(id, role) = "IBME:HYBRID-ID:v1" || role(P/C) || LP(id) || zeros(64-|id|)
```

默认编码宽度为 86 B。长度前缀区分 `A` 与 `A\0`，角色区分第一层与第二层；不以哈希替代身份，不额外依赖身份碰撞难度。底层接收规范编码，包装私钥保存原身份并核对其编码与底层冻结身份属性一致；Wang、IBS、CLI 继续处理原身份，层级顺序不变。

真实底层对 (1,1)、(64,1)、(1,64)、(64,64) B 身份的等长应用消息，胶囊和完整密文长度一致。该修复消除这项长度泄漏，**不等于证明旧教学 HIBE 的分布匿名性或安全参数已成立**。应用消息长度仍是公开的长度信息，隐私条件对应等长消息。

## 3. 参数、格式与尺寸

IBS 原样使用 [M2-B2](../2026-10-09-module/README.md) 的研究输入：N=256、(k,l)=(11,10)、η=1、κ=64、q=274877844481、γ₁=125440、γ₂=31470387200、γ₃=15270991360、d=28。仍未继承原文 Table 1 安全数字；M2-B1 的成本对照和模格安全草图适用条件继续核验。

底层 HIBE：n=8、m_matrix=168、q=524288、s₀=3、s=1、s′=1；仅将明文容量设为 32 B、编码身份上限设为 86 B。它是明确的教学参数，无安全等级。外部身份上限仍为 64 B。

消息容量同时满足：完整 Wang/BYTEAUTH 载荷为 `29563+|M| B`，包装默认允许 65536 B；送入 IBS 的是含接收身份和 89 B envelope 的完整编码，原 IBS 上限 4096 B。接收身份最多 64 B 时，统一应用上限为 **3924 B**。64 B 接收身份 + 3924 B 应用消息已在真实组合中验证，IBS 输入恰好 4096 B；3925 B 在使用随机数或签名前拒绝。

suite 为 `HIBE-IDPAD/SEED32/HKDF-SHA256/AES256GCM/v1`。外框按独立 PUBLIC/MASTER/LEVEL1/LEVEL2/CIPHERTEXT/AAD kind 以及固定长度前缀解析。密文仅包含 64 B 公开上下文、底层胶囊、12 B nonce 和带 16 B GCM tag 的消息体。AAD 还绑定 suite 和实际载荷长度。配置由 backend_id、原身份上限、载荷上限及胶囊上限组成，公钥上下文覆盖完整规范公钥。

总长、字段大小、未知版本、重复/截断/追加、身份绑定、后端标记及底层对象规范往返均检查。资源上限及异常规范已同步 IMPLEMENTATION_SPEC；同一解码器不接收旧裸 HIBE 密文作为新 hybrid 密文。私有 repr 隐去秘密，种子、DEM 密钥和 RNG 不持久化。

[固定 Sage 审计](hybrid-audit.json)实测尺寸如下；身份 Alice/Bob 为 5/3 B，测试消息长度为 0/32/3924 B，每个一次，无生产密钥。

| 对象 | 大小 |
|---|---:|
| 完整 IBME 公钥 | 252278 B |
| 发送者密钥 | 313695 B |
| 接收者密钥 | 85223 B |
| 缓存一个发送者的主状态快照 | 368849 B |
| Luo 签名 | 29455 B |
| 固定 32 B 种子胶囊 | 2452065 B |
| 空应用消息完整密文 | 2580256 B |
| 32 B 应用消息完整密文 | 2580288 B |
| 3924 B 应用消息完整密文 | 2584180 B |

固定身份宽度保证身份长度不改变胶囊数量，但旧逐比特 HIBE 仍产生约 2.34 MiB 胶囊。现阶段完成容量接线，没有完成压缩或同等级性能比较；不把标准混合包装宣称为项目原创 A+B<C。队友的真实 CHKP/多比特路线仍需要独立资源验收。

## 4. 实际攻击与对照

所有新目标无 XFAIL，签名候选使用**规范的新 Luo 签名格式**，外层 OTS 也实际验签成功；不能用旧 SisSignature 类型不兼容当作攻击被修复。

- 原 c1 最低位修改：原 HIBE 解出与修改前完全相同的 32 B 种子。Hybrid GCM 因完整胶囊 AAD 改变而拒绝；BYTEAUTH 也拒绝。负面对照没有改成破坏 magic 的容易输入。
- 不持发送者密钥：64 次公开零响应挑战猜测均被 IBS 拒绝；构造了一份真实 HIBE/DEM、合法新签名类型和有效外层 OTS 的完整冒名密文，接收者返回 BOTTOM，从未给目标 Unissued 发钥。
- 持有 Bob 的接收密钥：可解密合法载荷，并公开重加密原有真实签名/envelope。原 Baseline 接受相同 envelope 是正面对照；攻击者换新 OTS 公钥重签，BYTEAUTH 仍因内层承诺不一致返回 BOTTOM。
- 接收者修改 envelope/消息并保持旧真实 IBS 签名：新 DEM 和 OTS 均合法，仍在 IBS 验证处拒绝。签名挑战的规范 ±1 修改也被拒绝。
- Sage 只用公钥在 4 个独立评价点检查选定 `w₁=0,h=0,v=0` 的精确公开线性子路径：A 的秩为 10，增广矩阵秩为 11；选定挑战比例非零，`solve_right` 无解。它阻断这一固定精确求解目标，**不排除允许舍入区间、其他 w₁/h、格基求解或自适应伪造的全部攻击**。

有限公开猜测、秩障碍和篡改测试均不能替代完整不可伪造/匿名性证明。原 education 配置仍有两个认证反例，原严格 XFAIL 保留；新组合的未标记目标和旧负面对照分别记录。项目默认 education 未切为安全实例。

## 5. 验证与复现

硬件 Intel Core Ultra 9 275HX。Windows：Python 3.14.6、pytest 9.1.1、cryptography 49.0.0；指定 WSL Sage：Python 3.13.14、Sage 10.9、cryptography 49.0.0；隔离 wheel：Python 3.12.14、cryptography 50.0.2。审计 JSON 自动采集处理器、平台、库版本和 OpenSSL。

- Windows 最终新增批次 **67 passed**（HIBE 适配 42、真实协议/CLI 25）；指定 WSL 同一批次 **67 passed**。含跨进程 setup/发钥/签验、重复发钥一致、精确输入边界、身份编码绑定、非法输入及攻击。
- Windows 当前基础批次 **464 passed、2 xfailed**；旧协议/CLI + BYTEAUTH 另跑 **93 passed**。两批有重叠，不能相加；两个旧漏洞依然实测成立。
- Sage 审计：1 次 Setup、3 次完整诚实消息往返、1 次恢复后往返、3 次身份错配，以及上述公开伪造/接收者重签/c1 对照和 4 个秩点。固定随机带重放结果一致；自动环境采集改进后再次比较全部密码学结果/尺寸/公开密文摘要不变。私有快照、种子、DEM 密钥或掩码未写入 JSON。
- HKDF 与独立标准库 HMAC 的 RFC 5869 计算一致；AES-256-GCM 对照 [NIST CAVS 14.0 的 Count 0 向量](https://github.com/pyca/cryptography/blob/main/vectors/cryptography_vectors/ciphers/AES/GCM/gcmEncryptExtIV256.rsp)通过。标准库检查不证明整个自定义协议安全。
- 生成 wheel 后，用隔离进程只加载 wheel，真实组件加解密及公开/接收密钥重载通过，无源码目录依赖。

本轮首次大字节串用例产生过长的默认测试 ID，出现 4 个测试框架错误；显式短 ID 后通过，未为此调整加解密逻辑。随后发现身份长度泄漏，修复编码并重跑最终批次。初步 40/23 项统计已被最终 42/25 项替代，最终无失败测试。

```text
python -B -m pytest -p no:cacheprovider -q --tb=short tests/test_hybrid_hibe.py tests/test_luo_hybrid_ibme.py --junitxml=test-results/hybrid-windows.xml
wsl --cd /mnt/d/zcode_projects/ibme bash -lc '~/miniconda3/envs/sage/bin/python -B -m pytest -p no:cacheprovider -q --tb=short tests/test_hybrid_hibe.py tests/test_luo_hybrid_ibme.py --junitxml=test-results/hybrid-wsl.xml'
python -B -m pytest -p no:cacheprovider -q --tb=short tests/test_baseline_ibme.py tests/test_byteauth.py --junitxml=test-results/hybrid-legacy-cli.xml
python -B -m pytest -p no:cacheprovider -q --tb=short tests/test_encoding.py tests/test_lattice_core.py tests/test_prepared_hashing.py tests/test_known_security_gaps.py tests/test_luo_matrix_reference.py tests/test_luo_ibs_contract.py tests/test_luo_parameter_screen.py tests/test_luo_joint_parameters.py tests/test_luo_module_math.py tests/test_luo_module_backend.py tests/test_byteauth.py --junitxml=test-results/hybrid-basic.xml
wsl --cd /mnt/d/zcode_projects/ibme bash -lc 'PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -B -m experiments.research.luo_hybrid_audit --output docs/research/2026-10-09-hybrid/hybrid-audit.json'
python -B -m pip wheel . --no-index --no-deps --no-build-isolation --wheel-dir <仓库外输出目录>
```

远端工作流分成互相独立的基础和 hybrid 研究两批；hybrid 安装固定 cryptography 50.0.2，报告分别上传。远端状态以本提交对应的运行结果为准，本地结果不冒充远端结果。

## 6. 可运行入口

```text
python -m pip install ".[hybrid]"
python -m ibme.cli setup --params luo-module-research --state hybrid-research-state
python -m ibme.cli issue-sender-key Alice --state hybrid-research-state
python -m ibme.cli issue-receiver-key Bob --state hybrid-research-state
python -m ibme.cli encrypt --sender Alice --receiver Bob --state hybrid-research-state --in message.bin --out hybrid-demo.ibme-ct
python -m ibme.cli decrypt --receiver Bob --sender Alice --state hybrid-research-state --in hybrid-demo.ibme-ct --out recovered.bin
```

message.bin 由调用方提供，大小≤3924 B；state 应为新目录，私有文件不传入 Git。profile 名和 setup 输出明确是 research/none；后续命令由该 state 选择真实组件，不必重新手工选择原语。

## 7. 下一轮与 WIP

容量接线、身份长度这一项泄漏、固定密钥跨命令缓存及选定完整攻击对照已完成。下一轮主 AI 集中核验 **Luo 模格的精确 MSIS/Hint 界、成本与实际参数/缓存条件的论文对应**，给出是否可进入正式参数的明确结论；采用引用和有限核验，不默认重做整篇 QROM 或 Lean。不能把 64 次失败猜测写成所有攻击失败。

队友继续 CHKP 两层匿名 HIBE/格工具，交接时需要支持固定宽度编码身份及至少 32 B 种子，另报告真实采样、参数和资源。当前旧 HIBE 仍教学，待可信原语交接再替换。此 adapter 可复用公开接口，新的后端/配置版本另行放行。

尚未完成：正式 HIBE/IBS 参数准入、完整自适应/匿名/量子模型对应、所有格攻击排除、安全默认入口、位/种子压缩、并发和私钥存储、完整系统性能比较及组合优化。没有以绿色 CI 宣称 NIST、CCA、QROM 或全国一等奖条件已达成。

## 8. 修改文件

新增：`src/ibme/protocol/hybrid_hibe.py`、`src/ibme/protocol/luo_hybrid.py`、`tests/test_hybrid_hibe.py`、`tests/test_luo_hybrid_ibme.py`、`experiments/research/luo_hybrid_audit.py`、本目录 README/JSON。

修改：`src/ibme/cli.py`、`pyproject.toml`、`.github/workflows/basic-checks.yml`、`IMPLEMENTATION_SPEC.md`、根 README、PROJECT_RESTART、KNOWN_SECURITY_GAPS、主 AI 工作计划。

跨协议/CLI/规范/CI 的修改用于保持同一版本编码、参数边界和跨命令生命周期；未修改队友原语、旧 IBS/攻击求解器或采样算法。所有修改形成提交并同步远端。
