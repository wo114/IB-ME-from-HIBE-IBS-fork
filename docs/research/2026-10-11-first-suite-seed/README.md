# 首套集中闭环：真实 H/G 与固定 256 位种子生命周期

日期：2026-10-11。当前目标是先完成第一套集中闭环。本轮只推进 CHKP → Luo 模格 IBS → Wang/HYBRID/BYTEAUTH；备用候选、独立压缩和单项跑分继续后置。完整首套仍为 WIP，不把局部种子链当成完整 HIBE/IBME。

## 远端审阅

PR #8 的两份安全工作边界文档已审阅合并：头 `52a394e`，合并 `fc3e52e`。采用 CHKP/Luo/Wang 原论文引用、实现条件映射和组合前提核验，不重写基础归约；Luo §4.4 仍按 sketch 引用，不因此授予参数或后端准入。

## 实际新增的实现

上一轮 qFALL/原生 GPV 的输入还是外部给定矩阵块和 syndrome。本轮新增独立 `experiments/research/first_suite/`，定义真实有序身份 H/G，保存完整 256 位置私有状态，并以同一身份矩阵封装/解封装 32 B 种子。

| 原文依据 | 新代码 | 边界 |
|---|---|---|
| CHKP §5.3 / PDF22，H 为矩阵、G 为 syndrome | `identity.py`：完整公开配置/根矩阵上下文、身份分量数、长度前缀、角色域、固定位置、块计数器；SHAKE-256 有界拒绝到 Zq | 真实公开算法没有模拟器陷门；Oracle 只验证规范数据/资源，不证明配置语义、素性/秩、GenBasis或困难性 |
| §5.1 / PDF19，多位独立 syndrome、共享 s/b | `seed_kem.py`：固定 256 位、MSB 位序；一次抽 n 个均匀 s，D+256 个真实连续 Gaussian 取整噪声；D+256 模系数 | 奇模数距离与平局按原文。raw KEM 错身份可输出随机种子，必须由后续 AEAD/IBS 收口 |
| §5.2 / PDF20，最深层可省略委派基 | `leaf_state.py`：仅存256个短原像、公开scope和身份；终层从扩展父基采样，不做第二 RandBasis | 不保存采样器/RNG/根父叶基，首级可委派密钥及主密钥仍待后端交接 |
| §5.3 / PDF22，同一身份同一向量 | 固定 root/config/receiver/width/profile scope，每个 sender 保存位置0..255，跨进程复用 | syndrome 值可以碰撞，但地址不合并；唯一发钥树、可信存储及反回滚仍是环境条件 |
| 冻结状态事务 | 执行前保留FAILED，异常/KeyboardInterrupt/坏方程/坏范数保留墓碑，恢复后不重抽 | 组件只提供内存和快照；现有 CLI 锁/pending/成功失败保存尚未接新对象 |

身份顺序固定 `(receiver,sender)`。实跑使用既有 HYBRID 的 P/C 填充：原始 Bob/Alice 为3/5 B，内部均86 B。密文只有公开上下文/q/固定维度/模系数，没有身份或身份摘要。

## 格式和资源

`IBME:CHKP:RO-CONTEXT:v1` 保存 n/m/q、身份上限、256容量、调用方规范公开配置和根矩阵；q为uint64，模系数宽度由q推导。完整公开配置参与上下文：同一A但不同配置也产生不同H/G。配置的语义和实际噪声/采样profile对应由真实后端负责，不能凭opaque字节一致就准入。

`IBME:CHKP:FIXED-SEED-STATE:v1` 保存可信scope、按字节序排序的至多8个sender、READY/FAILED和READY的256个整数向量。恢复重算H/G，逐个核对维度、方程和范数。规范符号/长度前缀幅值禁止负零、前导零、重复/无序地址及尾随字段。

私有wire≤16MiB、单整数≤256bit；生成前按最大系数长度预留 `256*D*37` B。超限不保留地址、不调用采样器，不换plan或分批覆盖同一sender，也不淘汰已发地址。新组件不是旧32位缓存的扩容，没有更改旧有限原语硬上限/证书。

快照是敏感明文私有状态。它核验数学关系和预期scope，不证明Gaussian采样来源、不认证恶意本地写入、不抵抗旧快照回滚。探针私有文件只放被忽略的`test-results/`；本目录仅归档参数、计数和散列。

## 实跑和验证

精确结果、环境/源码指纹、测试命令和交付文件见本目录机器结果及`audit.json`。输入固定qFALL `b8eb4842fb80c36f7f3494930ea316472cb75793` 完整整数短基转换；复用既有ExtBasis/ToBasis、父级原生GPV随机化、独立精确验证Sage LLL和终层256个真实H/G目标。

| 预定输入 | 根/父/叶维度 | 父/叶s² | 3组种子的正确位/错误位 | 原始KEM wire / 私有快照 | 整段诊断耗时 |
|---|---|---|---|---|---|
| q=17,m_bar=8,n=1 | 13/26/39 | 62320/252769920 | 387/381 | 392/70783 B | 1.089 s |
| q=1073741827,m_bar=48,n=1 | 79/158/237 | 2441960/63276067520 | **768/0** | 2069/457248 B | 496.547 s |

各输入只执行1个预定公开测试流，生成1套256个原像后使用3组32 B种子：全零、全一和独立公开测试散列。不是768个新私钥样本。真实噪声alpha=4/q，q*alpha=4，tail64/mass96/precision160；每次封装实际独立噪声调用分别295/493，与D+256一致。三个错身份组合的原始种子均不同，但raw KEM不返回BOTTOM；尚未用这个组件替换完整协议。

两组快照均经新进程恢复，无新增私钥抽样，不加载native sampler，快照字节保持。较大行恢复后3个种子散列全部匹配；小q的3个散列均不匹配，错误没有被恢复流程隐藏。强制KeyboardInterrupt的第二地址恢复后仍阻止采样；这是状态反例验收，不是实际GPV中止率估计。截断/追加/错误版本3个密文格式对照均拒绝。软件环境为规定的WSL Sage10.9/Python3.13.14，CPU为Intel Core Ultra9 275HX，完整环境指纹见audit。探针耗时包含基/GS/随机化/规约/256采样/恢复/六次KEM，不是公平端到端性能基准。

最终相关回归：Windows **82 passed,1 skipped**，WSL Sage **194 passed**，均无失败；可移植新组件单独Windows **36 passed,1 skipped**。这些批次相互重叠，不相加为全仓测试总数。Sage batch包含新组件、有限GPV/实际原生链、取整噪声与既有叶缓存/恢复检查。没有重新运行整个仓库测试或声称全仓安全通过。

小q是预定解码失败对照，不能按方程通过改写成可用参数。较大q也仍为n=1；原生TV/最坏随机带/生产RNG、根近均匀及实际LWE成本未准入。现在具有真实256位置wire和生命周期，仍无形式安全结论。

多位G地址是明确定义的独立位置扩展。最终引用对应需把256位置的G查询和多位杂合代价计入；不能直接沿用单比特Theorem5.2的原查询预算。底层公开根、采样分布及实际困难性门槛也不因多位功能通过而消失。

```bash
# WSL仓库根目录，已完成上轮qFALL本地编译；仅预定公开教学输入。
PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -m pytest -p no:cacheprovider -q --tb=short \
  tests/test_first_suite_identity_state.py tests/test_first_suite_seed_sage.py \
  tests/test_ibme_rounded_noise.py tests/test_ibme_noise_budget.py \
  tests/test_chkp_leaf_cache.py tests/test_chkp_leaf_cache_wire.py \
  tests/test_chkp_leaf_cache_audit.py \
  --junitxml=test-results/first-suite-lifecycle-regression-sage.xml

PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -m experiments.research.first_suite.lifecycle_probe \
  --only-q 1073741827 --private-directory test-results/first-suite-seed-qbig/private \
  --output test-results/first-suite-seed-qbig/result.json
```

Windows可移植测试用明确公开toy向量验证状态，不冒充Gaussian测试；Sage项使用真实有限GPV/原生GPV、实际取整噪声及私有恢复。缺少Sage或binary的skip不是通过。首次旧缓存子进程回归缺少`PYTHONPATH=src`，已按上述环境修正复跑，没有修改队友文件。

## 首套闭环账本

| 验收项 | 当前证据与状态 | 剩余工作 |
|---|---|---|
| 固定构造/接口 | 已冻结Wang、两层匿名ROM HIBE、适应性IBS、身份顺序 | 不增加Boyen–Li任务 |
| 真实H/G、256原像、私有恢复 | 本轮组件和实跑，范围以机器结果限定 | 合入真实HIBE/磁盘生命周期 |
| 实际参数/生成/采样条件 | 现有有限参考、噪声账本和教学诊断 | 同组n、根近均匀、GS/宽度、alpha、经典/量子成本、真实熵及误差/资源 |
| CHKP七入口/密钥对象 | 尚无已交付完整`src/ibme/hibe/chkp.py` | 主/父固定发钥、完整参数、公私钥绑定、字节适配、加载器/contract |
| Luo/Wang引用条件 | 真实IBS四算法、缓存和引用边界已存在 | sketch引用限制、实际条件和工程差异最终对应 |
| 完整组合/攻击 | 既有教学ABB10＋Luo＋HYBRID/BYTEAUTH可复用 | 换真实CHKP；四种匹配、伪造/冒名/自我伪造、全字节篡改和非法编码，无安全XFAIL放行 |
| 系统稳定/成本 | 组件日志和旧组合基线 | 首套批量正确性、跨进程失败恢复、冷/热时间、内存、密钥与密文；本探针总耗时不算生产基准 |

**整体目标继续保持，第一套尚未完成。** 下一项优先完整主/父钥及七入口，同时解决生产采样与实际选参；新组件不替代这些要求。声明固定`security_claim:none,backend_admitted:false,parameters_are_formal:false`，经典ROM引用不升级成QROM，测试不能替代安全性论证。旧education两个认证反例也未由本轮消除。
