# 截图算法清单与当前实施计划核对

两张截图的 8 条 HIBE 和 11 条 IBS 均已有路线 ID、owner、任务与下一步，不需要另造一份重复目录。本批修正过期的 CHKP/Luo/MP12 状态和 Foo–Li 表述，并把 Wang+PW 的新研究代码登记为实际完成范围。历史 `2026-10-10-foundations/catalog.json` 的 17 条记录保留为当天快照，当前 19 条入口是 [算法目录](../../../ALGORITHM_CATALOG.md)和[三人总计划](../../../workplans/三人方案分工与统一框架交付.md)。

| 截图路线 / ID | owner / task | 已有代码及下一实施项 |
|---|---|---|
| CHKP-ROM / chkp-rom | A / A1 | PR14已有真实研究六方法/整链/CLI；后续正式困难参数与资源，不再重补公开后端 |
| ABB-ROM / abb-rom | A / A2 | PR15有原文根/位/委派组件，完整HIBE与对象仍WIP；先修恢复交付缺陷再推进两层 |
| LATTE / latte | C / C1 | 作者源与局部运行已有；复验缓冲采样、完整两层及匿名条件 |
| GKR2025 / gkr2025 | A / AR | 原文已存；编译器、匿名扩展与混淆依赖/成本先核 |
| Zhang2020 / zhang2020 | C / CR | 环工具已有；澄清可委派陷门/逆元/模数方向，再实施真实SamplePre |
| ABB标准选择性 / abb-standard-selective | A / AR | 提取原稿§8/Theorem33的算法、列数与宽度，独立于ROM实现 |
| CHKP标准模型 / chkp-standard | A / AR | 提取§5.4可容许哈希、层深/额外维度、匿名范围，不拿ROM代码代替 |
| Lai理想格HIBE / lai-ideal-hibe | C / C1 | §5.1–5.2/定理10、标签逆元及真实委派先核；通用环库不是作者HIBE |
| Luo模格 / luo-module | B / B1 | 四算法、C64B与恢复已研究收尾；固定版本维护，不重写已有算法 |
| Luo矩阵 / luo-matrix | B / B2 | 已有真实四算法；保留必要对照与失败参数负控 |
| Foo–Li / foo-li | B / B3 | 已有setup/extract/sign_raw/verify与种子/恢复的真实研究生命周期；补共同对象/五方法/稳健服务与条件核验 |
| Wang+PW / wang-pw | B / B4 | 本批真采样、完整转换五方法与严格恢复；后继正式参数、固定服务映射、公开登记和真实HIBE配对 |
| SRGG2025 / srgg2025 | B / B5 | 代数/gadget/几何已有；补真实相关扰动与提取；SampleF/卷积/HNF分布及完整签验仍独立待做 |
| Yu2026 / yu2026 | B / BR | 同态/电路组件已有；选择真实PRF有限电路、核范数增长，再委派/采样/IBS |
| Sageloli-SIS / sageloli-sis | B / B5 | 计数已有；核固定服务游戏、q=3^k复合模数陷门和SampleD，再四算法 |
| Sageloli-RSIS / sageloli-rsis | B / B5 | 环基础已有；复合模数环采样、固定服务、实际wire/MB容量，不套素数NTT |
| BNN+ML-DSA / cert-ml-dsa | C / C2 | 普通签名源已有；共享认证转换、机构证书/用户键/消息绑定、KAT与完整IBS |
| BNN+Falcon / cert-falcon | C / C2 | 普通签名源已有；复用转换核心，独立适配格式/熵/解析，验完整认证载荷 |
| Xie-NTRU-IBS / xie-ntru-ibs | C / C3 | 原稿与NTRU工具已存；澄清模数/逆元、真实Gaussian/拒绝及原生四算法 |

上述 ID 以当前机器任务表为准，显示名称不影响算法计数。MP12 compact 研究变体仍属于原计划下的不同 profile，不能因此把独立论文路线数改成 20。BNN两项和Xie属于C，本批没有把未实现部分偷偷算给B完成。

Foo–Li 的 `sign_raw` 命名或共同接口缺失不抹去原文研究算法已经实现的事实；同时它保留原始样本和中止，不保证每个原始样本均通过 Verify。代码完成、工程接入、参数和安全条件分别登记。
