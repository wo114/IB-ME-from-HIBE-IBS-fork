# CHKP 2011 作者稿 `3m` 路线：论文与代码对应

本记录固定 Cash–Hofheinz–Kiltz–Peikert《Bonsai Trees, or How to Delegate a Lattice Basis》的 **2011-06-14、36 页作者稿**，以仓库内[论文 PDF](../../../../papers/2010_bonsai_trees_cash.pdf)为准，SHA-256 为 `b1d8a2ae0e9d4e5c9145bbc6dc864090605c12a5b76149aa0684d62a8815d2ce`；用户提供的 PDF 与它逐字节相同。这里的 `3m` 指深度二的公开矩阵 `A0 || H(receiver) || H(receiver,sender)`，并非 EUROCRYPT 2010 出版版的深度二布局。本记录只审查作者稿 §5.1–5.3 与当前代码，不将研究功能、论文安全定理、参数困难性混为一个验收项。

## 已有功能与对应位置

| 2011 作者稿位置及步骤 | 当前代码与调用路径 | 对应程度及界限 |
|---|---|---|
| §5.3，PDF p.22：`Setup` 输出 `A0`、完整根基 `S0`；`H` 给每个有序身份前缀一块 `n×m` 矩阵，`G` 给身份目标 | [旧 CHKP 后端](../../../../src/ibme/hibe/chkp/backend.py) `CHKPHIBE.setup`；[身份预言机](../../../../src/ibme/lattice/chkp/identity.py) `ROHIBEContext` | 根通过 **MP12 GenTrap 转完整基**获得，不是论文引用的 AP09 `GenBasis` 字面实现；SHAKE-256 域分隔/拒绝取模是一个具体哈希实现，不因此获得随机预言机模型证明。`G(path,position)` 为 256 个位置生成独立地址。 |
| §5.3，PDF p.22：深度 `t` 的 `A_id=A0||H(id1)||…||H(id1,…,idt)`，`y_id=G(id)` | `ROHIBEContext.parent_rows`、`leaf_rows`、`targets`；[一级 KEM](../../../../src/ibme/lattice/chkp/level1_kem.py)；[深度二 KEM](../../../../src/ibme/lattice/chkp/seed_kem.py) | 接收者一级用 `2m`，`(receiver,sender)` 二级用 `3m`，身份次序固定；256 位种子通过 256 个位置目标摊销，而非原文单比特演示。 |
| §5.2，PDF p.19–20：`Extract` 同时生成后续委派的短基 `S_id` 和当前节点解封装原像 `x_id`；叶可以省略短基 | [版本化服务](../../../../src/ibme/hibe/chkp/author2011.py) `Author2011HIBE.extract` 先调用 `CHKPHIBE.extract` 产生一级完整基，再由 `sample_level1_preimages` 从根基的隐式 `ExtBasis` 对 256 个 `G(receiver,j)` 取样；`derive` 调用旧 CHKP 的 256 原像叶路径 | 新一级密钥保存基和 256 原像；二级只保存固定原像，不保存叶扩展基。一级与二级分别校验方程、范数、公开参数及身份绑定。两次采样使用同一公开扩展矩阵，各自独立取随机数；“符合原文所需分布”的有限误差映射尚需另核。 |
| §5.2，PDF p.21：变深度匿名扩展把密文 `b` 补至 `(d+1)m`，多余坐标独立均匀；解密忽略填充 | `encapsulate_level1`：一级 `2m` 个真实 LWE 坐标再加 `m` 个独立均匀坐标；`decapsulate_level1` 只读前 `2m`。`encapsulate_seed` / `decapsulate_seed`：二级 `3m` 坐标全部真实参与 LWE。两层均用同一种 `Author2011Ciphertext` 外部封装。 | 长度与编码布局已对齐这个修改；它不是身份匿名性的完整游戏证明。原始 CPA KEM 对错误身份或任意篡改可以输出任意 32 字节，外层 Hybrid 的认证拒绝需独立验收。 |
| §5.3，PDF p.22：重复 `Extract` 必须返回同一个 `x_id`，可使用有状态服务 | `Author2011MasterSecret.issue/lookup/to_bytes/from_bytes` 保存一级 256 原像并关联旧父基状态；失败地址保持占用；旧叶状态保存二级原像；新对象使用 `chkp-author2011-3m-v1` 独立 wire | 在同一持久状态内重复发钥可复用且不重采样；裸快照的回滚/克隆攻击不是字节对象本身能阻止的。服务的持久化事务、断电阶段与并发还须在真实 CLI 生命周期中核对。 |
| 项目需要 `(receiver,sender)` 两层 HIBE 接口 | [默认注册](../../../../src/ibme/assembly/registry.py) 的 `chkp-author2011` 选择项，`hybrid-research` 使用 `CHKPParams` 的 n=2 配方；一级加解密另由 `Author2011HIBE.encrypt_level1/decrypt_level1` 提供 | 通用装配入口使用二级 HIBE；一级节点加解密是该后端的额外方法。旧 `chkp` ID、对象和证据保持独立，不应将旧实跑累计到新 ID。 |

## 原文、实现和安全陈述的差距

1. **论文自身维度不一致。** 2011 作者稿 §5.3 在 PDF p.22 明写深度 `t` 为 `(t+1)m`，而同页 Theorem 5.2 以维度 `dm` 的 KEM 为归约目标，PDF p.23 模拟器只解析 `A0,…,A_(d−1)`，并只为挑战身份的 `t−1` 个 `H` 前缀预置挑战矩阵。对于深度二真实加密的 `3m` 前导，这套印出的模拟器/截断说明没有覆盖所有坐标。不能把 Theorem 5.2 或出版版 Theorem 5.3 原封不动标在本服务上；需找到作者勘误或逐游戏补齐映射及损失，才能提出相应安全结论。
2. **匿名性另有前提。** 作者稿 p.21 给出变深度均匀填充的说明；Theorem 5.2 的 `aid-ind-cpa` 是自适应身份 IND-CPA，并非身份匿名定理。一级填充、真实 LWE 前导与均匀分布的切换、两端身份及 Wang 组合所需的混合游戏和调用损失都未因源码存在而自动闭合。项目把论文安全/匿名作为研发工作前提，但公开状态仍应是 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。
3. **根算法存在明确替换。** 现可调用 HIBE 的 `setup` 用 MP12 GenTrap/完整基，保留 CHKP 的 `ExtBasis/RandBasis` 父委派及真实 256 原像采样。新增的[AP09 GenBasis 根](../../../../src/ibme/lattice/chkp/ap09_root.py)是独立、可测试的研究组件，**尚未接入 `Author2011HIBE.setup`**。若要求根也逐算法照 AP09，需先为 AP09 的维度、近均匀界、父宽与对象预算找到同一可执行参数，再接线实跑；不能仅把组件存在当作全链使用。
4. **参数与有限实现未正式准入。** 默认 n=2、q=`1099511627791`、m=127、父 `2m=254`、叶 `3m=381`，256 位种子；这些是研究执行参数。KEM 正确性噪声、根矩阵分布、有限 Gaussian/截断误差、实际攻击成本、父基表示和对象资源必须按同一组参数核算。当前注册项的组合预检只是静态门，不能证明真实生成或困难性。`q`、维度及完整基的代码上限也尚不支持既有高维目标。

## 截至本记录的可复核检查

在仓库根使用指定 WSL Sage 环境运行：

```sh
PYTHONPATH=src:. PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
~/miniconda3/envs/sage/bin/python -m pytest -q \
 tests/test_chkp_level1_kem.py tests/test_chkp_ap09_root.py tests/test_chkp_author2011.py
```

合并定向回归在同一入口后追加：`tests/test_hybrid_hibe.py tests/test_chkp_assembly.py tests/test_cli_master_state.py tests/test_cli_receiver_state.py tests/test_research_state_integrity.py`。

新增解析与 Hybrid 容量负控后，三文件子集为 **29 passed**（新版服务 8 项）。一次同版本 WSL Sage 定向回归同时覆盖这三文件、Hybrid 本体、CHKP 装配、CLI 主状态/接收状态及研究状态完整性，结果 **147 passed、0 failed、0 skipped，164.51 s**；这已包括29项子集，不重复累加。一级 KEM 测试使用真实有限 GPV 的 `ExtBasis` 采样及真实舍入噪声，也有公开可解的教学代数夹具；AP09 测试只覆盖独立根组件；新服务的对象、持久复用、失败占址、版本与组合预检基于公开可解代数夹具。功能实跑证据在下文单列。

第一组**单次系统 CSPRNG**研究运行采用 n=1、q=`17179869209`、m=51、父维 `2m=102`、叶维 `3m=153`、`lll_policy=none`。该候选的公开父/叶噪声充分式检查返回 `True`；`setup` 用时 3.760 s，`extract` 用时 40.547 s，并实际生成公钥 2,000 B 和一级密钥 264,146 B。随后 `derive` 约 73.64 s，在 `FirstFiniteGPV` 独立有限采样配置要求平方宽度落在 `1..2^88` 的检查处中止，**没有生成二级密钥，也没有运行该候选的二级 KEM 或完整组合**。私有状态仅保留在被 Git 忽略的 `build/outputs/chkp-author2011-n1-real-2026-10-18-v2/`，失败地址墓碑保留；不将其加入仓库。

第二组独立系统 CSPRNG 运行保持 n=1、q=`17179869209`、m=51，预先把 `lll_policy` 固定为 `checked`，`epsilon_bits=16`、`regularity_bits=8`，没有在同一私钥失败后改策略重抽。`setup` 3.94 s、`extract` 11.45 s、`derive` 12.28 s，总 27.90 s；同一组一级、二级 32 B seed KEM 都正确解出。随后在新进程中分别恢复 public/master/parent/leaf/一级密文/二级密文，六类对象均通过规范往返；三类私有对象与 public 绑定为真，两层分别解密出 32 B。恢复阶段在 Sage 初始化后使 `os.urandom` 和 `SecureRandom.read` 遇调用即失败，仍以 0.61 s 完成，因而该阶段没有请求新私有熵。原进程只记录种子匹配布尔值，未持久化原种子。原始私有收据 `restoration.json`、恢复脚本与对象保存在被 Git 忽略的 `build/outputs/chkp-author2011-n1-checked-2026-10-18/`，不入库。两组 n=1 都只是研究执行性检查，不是困难性参数；单次成功也不能估计罕见中止率或证明论文的分布与安全结论。

固定实现提交 `f80ef65` 上另用第二组**尚未签发 receiver 的真实根快照**运行 selected `chkp-author2011 + luo-module/compact + Hybrid + BYTEAUTH`。用户身份先由 Hybrid 编为底层 86 B，故使用全新 receiver/sender 地址，不复用原语实跑的原始地址；Luo 密钥和 CHKP 一级/二级密钥都在这次组合流程真实生成。19 B 消息诚实解密相等，密文位篡改返回 BOTTOM。整次 51.59 s，公开组合公钥 250,150 B、主状态 943,789 B、接收者密钥 568,506 B、完整密文 117,011 B；suite digest 为 `237e1baa03cf3a0d5cdefc2c8f81ebce472924883de0c2fe68c63cc448ad4964`。首次组合脚本缺少仓库根 `PYTHONPATH`，在新 CHKP 签发前中止；该环境失败保留在另一个目录，不并入成功次数。

同一固定提交和 suite 随后做了**17/17 组合负控**，耗时 15.08 s：新进程规范加载公钥、主状态、发送者钥、接收者钥和密文；Sage 初始化后对运行期 OS/项目随机源设遇调用即失败的守卫，仍能用已缓存叶诚实解密 19 B 原文。只错接收者、只错发送者、双方都错三格均 BOTTOM；密文位篡改、外层签名篡改、截断、追加、重复字段、有效新外层签名下的内层密文篡改、有效新外层签名和 AEAD 下的 Luo 签名篡改、随机字节伪造均拒绝。负控中没有新 CHKP 私有采样或新地址；另造有效密文和 Luo 发送者使用系统随机源，不应称全实验零熵。逐项布尔值与输入哈希见被 Git 忽略的 `build/outputs/chkp-author2011-n1-checked-2026-10-18/combo-v2/receipt.json`、`combo-negatives-f80/receipt.json`；私钥、密文原件均只在该私有目录，**不提交**。

### 全新根一键复放与命令行

仓库加入[可重跑入口](../../../../experiments/research/chkp_author2011_lifecycle.py)，在一个**不存在的** `build/outputs` 子目录内使用系统 CSPRNG 做同一根下的两种一级身份、两层 CHKP 种子、Luo module/compact＋Hybrid＋BYTEAUTH 组合，并启动另一 Sage 进程解析对象、解密及执行负面验收。它不会使用公开可解夹具、固定测试随机数或失败后同址重抽；目录内含私钥，必须留在本地并保持 Git 忽略。复放命令（WSL 仓库根，运行前选全新输出目录）：

```sh
timeout --signal=TERM --kill-after=10s 300s \
  ~/miniconda3/envs/sage/bin/python \
  experiments/research/chkp_author2011_lifecycle.py \
  --output build/outputs/chkp-author2011-my-fresh-run
```

入口默认 `n=1, q=17179869209, m=51, lll_policy=checked, epsilon_bits=16, regularity_bits=8, alpha=4/q`；用户原始直接身份 28/26 B、组合身份 27/25 B，Hybrid 底层均编码为 86 B；种子 32 B、应用消息 19 B。初次全新根运行在 `f80ef65` 服务及 `5086cbf` 入口上用时122.67 s；随后修正 `seed32` 前置门和损坏预像的解析错误类型，在 `5a5006f` 服务及同一入口上**另取全新根**复放，118.15 s 完成。最终运行再次通过两级真实种子一致、所选组合诚实消息一致、跨进程 **15/15** 规范恢复与无新私有熵解密检查及 **11/11** 负控（三种身份错配、密文/签名篡改、截断、追加、重复字段、随机伪造等）。最终服务 SHA-256 为 `45ef1ff2006ff96c9f6da8db7f057bafc4ec86a23a8442b19395c367488fb9f7`，入口 SHA-256 为 `7e86d55ea84afaa5372b0a20741b37931fccd2b753a8e452b6f431855bf76fbf`。负控使用已有叶，不产生新 CHKP 私有采样；其余过程使用系统随机数。仓库内[脱敏功能摘要](evidence/functional-summary.json)只保留版本、参数和布尔结果；原始 `receipt.json`、`restoration.json`、`negatives.json`、状态和密钥只留在本机忽略目录。

另在 `f80ef65` 固定代码下，经 `python -m ibme.cli` 对[公开研究参数](evidence/cli-research-params.json)执行 `check`、独立进程 `setup`、签发 Luo sender、签发 CHKP receiver、28 B 加密及另一进程解密，均为 exit 0，恢复明文字节 SHA-256 与原文相同。翻转密文中间一个字节的 1 bit 后，新进程解密 exit 1、输出 `BOTTOM`，没有生成明文文件。该 CLI 流程使用了**另一组全新根**，不是从上面一键入口复制私钥；私有命令/收据保存在 `build/outputs/chkp-author2011-cli-real-2026-10-18-a1/`。这验证了当前单写者 CLI 生命周期的正常路径和一次篡改拒绝，尚未实测断电阶段、并发冲突或状态回滚。

实测环境：华硕 TX Gaming FX608LM，Intel Core Ultra 7 255HX，主机物理内存约 33.68 GB；WSL2 Linux 6.18.33.2、可见内存约 16.43 GB，指定 conda Sage 10.9 / Python 3.13.15。每组所述全新根仅运行一次；耗时是单次墙钟时间，不是统计分布或跨算法公平性能排名。最终解析修复另经 WSL Sage `tests/test_chkp_author2011.py` **10 passed**；此前147项定向回归针对修复前版本，其有效路径未变，但没有把它记作修复后整套回归。

这些是 n=1 小参数下的单组原语与组合功能证据，不估计安全强度、罕见失败率或生产资源。2011 作者稿定理的 `dm/3m` 冲突、根替换、匿名与 Wang 安全映射及正式参数仍未闭合；旧 `chkp` ID 的收据不转记到新后端。本文件是对应关系与当前研究验收边界，不是安全证书。
