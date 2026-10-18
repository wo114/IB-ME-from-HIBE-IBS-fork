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

本地结果 **27 passed，0 failed**。其中一级 KEM 测试使用真实有限 GPV 的 `ExtBasis` 采样及真实舍入噪声，也有公开可解的教学代数夹具；AP09 测试只覆盖独立根组件；新服务的对象、持久复用、失败占址、版本与组合预检基于公开可解代数夹具。三者都不能替代同一非教学参数下的系统随机根→一级基与 256 原像→二级 256 原像→两层加解密→独立进程恢复实跑。

第一组**单次系统 CSPRNG**研究运行采用 n=1、q=`17179869209`、m=51、父维 `2m=102`、叶维 `3m=153`、`lll_policy=none`。该候选的公开父/叶噪声充分式检查返回 `True`；`setup` 用时 3.760 s，`extract` 用时 40.547 s，并实际生成公钥 2,000 B 和一级密钥 264,146 B。随后 `derive` 约 73.64 s，在 `FirstFiniteGPV` 独立有限采样配置要求平方宽度落在 `1..2^88` 的检查处中止，**没有生成二级密钥，也没有运行该候选的二级 KEM 或完整组合**。私有状态仅保留在被 Git 忽略的 `build/outputs/chkp-author2011-n1-real-2026-10-18-v2/`，失败地址墓碑保留；不将其加入仓库。

第二组独立系统 CSPRNG 运行保持 n=1、q=`17179869209`、m=51，预先把 `lll_policy` 固定为 `checked`，`epsilon_bits=16`、`regularity_bits=8`，没有在同一私钥失败后改策略重抽。`setup` 3.94 s、`extract` 11.45 s、`derive` 12.28 s，总 27.90 s；同一组一级、二级 32 B seed KEM 都正确解出。随后在新进程中分别恢复 public/master/parent/leaf/一级密文/二级密文，六类对象均通过规范往返；三类私有对象与 public 绑定为真，两层分别解密出 32 B。恢复阶段在 Sage 初始化后使 `os.urandom` 和 `SecureRandom.read` 遇调用即失败，仍以 0.61 s 完成，因而该阶段没有请求新私有熵。原进程只记录种子匹配布尔值，未持久化原种子。原始私有收据 `restoration.json`、恢复脚本与对象保存在被 Git 忽略的 `build/outputs/chkp-author2011-n1-checked-2026-10-18/`，不入库。两组 n=1 都只是研究执行性检查，不是困难性参数；单次成功也不能估计罕见中止率或证明论文的分布与安全结论。

本批代码仍在集成，提交哈希以最终合并的实现提交为准；本文件是对应关系及当前验收边界，不是独立安全证书。除静态预检外，`chkp-author2011` 与 Luo/Hybrid 的真实组合数据应以该版本的实际运行收据为准，不能引用旧 `chkp` ID 的成功记录替代。
