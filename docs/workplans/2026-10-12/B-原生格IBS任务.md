# B：原生格基 IBS 任务书

日期：2026-10-12。责任以[总计划](../三人方案分工与统一框架交付.md)为准，具体任务 ID 见[tasks.json](tasks.json)。B 接现有 Luo owner 的实物，按原生论文路线扩充；不另写 HIBE 或公共 IBME。

## 1. 顺序与明确取舍

| ID | 必须交付 | 不能当作完成 |
|---|---|---|
| B1 / P0 | PR #9 Luo 模格交接、C64B 完整参数绑定、恢复与生命周期、公开登记提案 | PR #11 中引用的外部收据不等于 helper 已合并；教学 HIBE 接线不等于 CHKP+Luo |
| B2 / P1 | 保留 Luo 矩阵真实参考和负控，必要接口修复、与模格同口径对照 | 不重新实现已有四算法；被筛查否定的参数不填正式推荐位 |
| B3 / P1 | Foo–Li 条件/资源核验后补共同 IBS 五方法与固定身份服务 | 现有 runtime/`sign_raw`、固定随机带局部等式不等于完整 Sign 或安全后端 |
| B4 / P2 | Wang 基本 IBS + Pan–Wagner 自适应转换备选 | 基本 IBS 非自适应性质不自动升级，两个盐不能代替模型对应 |
| B5 / P2 | Sageloli SIS/RSIS 与 SRGG 分批推进，先核固定服务/采样/有限成本 | 环代数、gadget 或论文参数计数不等于完整 IBS |
| BR / P3 | Yu 标准模型的 PRF/电路/参数成本与实施入口 | 已有同态等式不是实际 PRF、完整 IBS 或 Wang 的标准模型组合 |

先收尾现有 Luo；新增 SIS 主编码优先比较 Foo–Li 已有生命周期可复用程度、原文适配条件和资源，再选择可闭合的一条。Foo–Li 受阻时推进指定 Wang+PW 核验，保留原因；Sageloli/SRGG 不抢占首批。

## 2. 读原文与已有实物

- [公共规范](../../../IMPLEMENTATION_SPEC.md)、[IBS API](../../../src/ibme/ibs/api.py)、[Luo 专属契约](../../specs/luo-ibs.md)、[Luo 主线决策](../../research/2026-10-11/IBS版本决策-模格版主线.md)。
- [Luo 论文](../../../papers/2024_ibs_without_trapdoors_luo.pdf) §3/§4，[PR #9](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/9)以接收时的固定提交为准，当前审查头为 `e5e0b97`。
- [Foo–Li 论文](../../../papers/2023_tightly_secure_ibs_foo.pdf)、[经典 ROM 条件与修复路线](../../research/2026-10-04-round7/FooLi经典ROM证明补全与修复路线.md)、[研究 runtime](../../../experiments/research/foo_li_runtime_reference.py)。
- [Wang/PW 固定服务审查](../../research/2026-10-04-round3/Wang与PanWagner固定密钥接入审查.md)、[候选目录](../../ALGORITHM_CATALOG.md)及其 Sageloli/SRGG/Yu 链接。

安全工作引用原文定理并逐项对应查询/腐化、固定用户密钥、抽盐/种子、采样和参数，不默认重做 QROM 证明。改变算法时明确原文定理不再自动适用的部分。

## 3. 文件边界

Luo `src/ibme/ibs/luo*.py`、对应 tests、experiments 先与正在写的 owner 交接；不得覆盖其未提交修改。新增 `foo_li/`、`wang_pw/`、`sageloli/`、`srgg/` 独立后端、codec/参数/测试归 B。

模块环/NTT/拒绝工具由 B 认领具体文件；Sageloli 的复合模数工具不得套现有素数 NTT。矩阵 Gaussian/陷门接口复用 A；NTRU/外部 C 工具可请求 C。公共 registry、API、协议、CLI、共同 runner 由统筹写；交登记提案。材料放 `docs/research/team-b-delivery/<批次>/`。

## 4. 第一批收尾内容

1. 固定 PR #9 提交及文件清单，核 C64B 17 字段、默认/reference/compact 是否保持语义、恢复是否绑定全参数；核本地代码与外部测试版本。
2. 实际执行 Luo 相关原语/codec/恢复回归，记录真实范围与失败；与 PR #11 最终装配接口复跑受影响组合，不拿 `0bf0855` 的旧 API 收据替代。
3. 交 Luo 对象/状态/参数/容量/最大签名长度的登记提案；完整签名大小与内部方程失败层分开。C64B 的有前提中止指数不得说成安全位数。
4. Foo–Li/Wang+PW 小决策表：现有代码、固定服务/经典 ROM 前提、Gaussian/范数条件、非平凡 SIS 参数与成本、需要改的最小对象。选择下一主编码批次并说明原因。

每批用已有实际测试，不为文档重新跑无关昂贵采样。参数/模型尚未正式准入不妨碍满足研究执行条件的真实接入，但不能削检查或用教学伪造签名冒充目标算法。

## 5. 每个新 IBS 的完整判据

五方法 setup/key_extract/sign/verify/load_signature；随机源经构造函数注入。对象严格序列化、全参数/公钥/身份绑定、固定身份多消息与恢复、中止语义、消息范围和资源限额均有实物。认证方程、挑战/盐、范数、拒绝与分布按该论文实施。

测试包括诚实反复签名、错误身份/消息/主公钥、随机/公开伪造、截断/追加/重复/错误参数、状态恢复和中止。交参考差分、factory/decoders/参数/格式/容量提案，统筹登记后与每个已就绪 HIBE 运行组合。

同批交论文—算法—参数—代码映射、原始收据/环境/提交、完整 IBS 尺寸/耗时、算法章节及限制。当前未正式准入配置保持 none/false；功能通过不是 SIS/MLWE/MSIS 证明。Sage 使用 WSL `~/miniconda3/envs/sage`。
