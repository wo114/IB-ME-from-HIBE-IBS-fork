# C：结构 HIBE 与工程 IBS 对照任务书

日期：2026-10-12；状态刷新：2026-10-18。责任以[总计划](../三人方案分工与统一框架交付.md)为准，任务 ID 见[tasks.json](tasks.json)。C 先做来源可靠、可复用且适配的路线；不是提前指定 LATTE 或 Falcon 为最终三代表。★ 2026-10-18：C1/C2/C3/CR 均已交研究批次，当前状态见第 0 节，原“第一批/第二批”是 10-12 计划。

## 0. 2026-10-18 状态

| ID | 当前状态 | 关键证据 / 未闭合项 |
|---|---|---|
| C1 | LATTE 已接入默认 registry/CLI：10 配置 338 检查、545 项 Sage、437 项 Windows、五档安装与原状态恢复通过；Lai 交 15 项资格反例，未实现 HIBE；Zhang 类型/模数资格已交 | [C 框架](../../research/team-c-delivery/2026-10-15-c-framework/README.md)、[Lai 资格](../../research/team-c-delivery/2026-10-15-lai-qualification/README.md)、[Zhang 资格](../../research/team-c-delivery/2026-10-15-zhang-qualification/README.md)；LATTE 匿名/修订采样/正式参数未准入 |
| C2 | 共享认证转换核心的 ML-DSA 三档与 Falcon 两档均已接入默认 registry：真实 LATTE 组合、CLI、零熵恢复与仓库外安装通过 | [C 框架](../../research/team-c-delivery/2026-10-15-c-framework/README.md)；强 UF/量子模型映射/固定服务/正式参数待，参数档不多计算法 |
| C3 | Xie 修订方程研究核（53 项无 skip）已交；公开零挑战伪造与模 q 平移反例保留 | [Xie 研究](../../research/team-c-delivery/2026-10-15-xie-study/README.md)；不是 IBSBackend，原稿/正式参数/整体误差和模型 WIP |
| CR | Zhang 理想格 HIBE 类型/模数资格已核，未补造 Derive | [Zhang 资格](../../research/team-c-delivery/2026-10-15-zhang-qualification/README.md)；无 HIBE 后端 |

**下一批（按 PROJECT_STATUS）**：① LATTE 匿名性、修订采样有限误差与正式参数映射；② 认证转换的强 UF、量子模型、固定服务条件与正式参数；③ 由统筹接入新组合（C 不另写 IBME），Xie/Zhang 保留研究材料不冒充原稿复现。

## 1. 三条主工作与储备

| ID | 顺序与交付 | 核验门槛 |
|---|---|---|
| C1 / P1 | LATTE 与 Lai 同批资格核验，先实现通过条件且成本可控的一条结构 HIBE，再补另一条 | 两层真实委派、收件人匿名与所需身份模型、实际采样、完整参数/资源；作者 C 代码存在不保证 Wang 适配 |
| C2 / P1 | 一份已发表认证转换核心，先 ML-DSA、后 Falcon 的两个 IBS 对照 | 普通签名 KAT → 完整转换 IBS → IBME 三层验收；固定发钥、身份/证书/用户公钥/消息绑定及严格 wire |
| C3 / P2 | Xie 原生 NTRU IBS 先澄清原文，再核有限输入和实施 | 模数/逆元文字、实际 Gaussian/拒绝、固定身份服务和定理前提未明前不冻结参数 |
| CR / P3 | Zhang 理想格 HIBE 的类型/委派/参数疑点与实施入口 | 不自行补造原文缺失 Derive，通用环组件不是 HIBE |

C1 原文核验和 C2 官方底层编译/KAT 可并行准备；实际主编码一次推进一个。先 ML-DSA 的理由是已有标准、参考代码与 KAT，优先建立清楚的封装边界；这是工程次序，不是性能/安全胜出结论。

## 2. 固定来源和需要核的条件

- [共同规范](../../../IMPLEMENTATION_SPEC.md)、[HIBE API](../../../src/ibme/hibe/api.py)、[IBS API](../../../src/ibme/ibs/api.py)、[候选总表](../../ALGORITHM_CATALOG.md)。
- [LATTE 原文](../../../papers/2024_quantum_safe_hibe_zhao.pdf)、[作者 GitLab](https://gitlab.com/raykzhao/latte)、[已复现标量缓冲问题](../../research/2026-10-11-public-reuse/README.md)。固定已审 revision `18cfbf9a671fca34785583b58ab9f28e3be21a3c`，保留 vendor 与补丁差分。
- [Lai 原文](../../../papers/2015_ideal_lattice_trapdoors_lai.pdf) §5.1–5.2/定理10、[来源与代码边界](../../research/2026-10-11-catalog/ideal-lattice-sources.md)。`lattice_lib` 只是工具，不能算作者 HIBE 实现。
- [认证转换原文](../../../papers/2006_generic_ibs_galindo.pdf) §3/Theorem 1；[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)、[官方 ML-DSA 参考仓库](https://github.com/pq-crystals/dilithium)、[Falcon 官方源](https://falcon-sign.info/)。冻结具体提交、版本和修订，历史 Dilithium 不默认等同 ML-DSA。
- [Xie 原文](../../../papers/2016_ntru_ibs_xie.pdf) §3/表2及[原文/代码疑点记录](../../research/2026-10-11-catalog/ntru-ibs-sources.md)。DLP 代码是 IBE/工具，不是 Xie IBS 或两层 HIBE。

LATTE 若匿名性尚无依据，可以交工程 HIBE 对照和真实运行材料，但不能宣称符合 Wang 普通隐私条件。Lai 的标签逆元、对象/委派类型、有限参数和原文匿名游戏都要落实，不能仅靠论文摘要入选。

## 3. 认证转换必须实现的内容

选定原文转换，准确给出机构发证、用户密钥生成、身份发钥/固定状态、消息签名和验证的算法对应，不自行删去绑定步骤。交机构公钥、身份签名密钥、证书/用户公钥/消息签名对象及完整编码，使用规范域分隔。

重点检查替换证书、替换用户公钥、换身份/消息、跨机构或参数重放、复制状态、截断/追加/重复字段，以及中止/崩溃后的发钥复用。调用受维护底层库的实际签名/验证，明确熵、格式、错误码、内存生命周期和测试向量版本。

机构与用户秘密钥分离，不让 HIBE/IBS 共用秘密陷门或随机噪声。ML-DSA 与 Falcon 共用公开转换框架，各有独立密钥类型、算法 ID 和参数/codec；两条普通签名适配不算两种新转换创新。

尺寸和时间统计完整 IBS：证书、用户公钥、消息签名、编码、验证链及固定状态开销。底层 KAT 通过、裸 Falcon 很小都不能替代完整比较。转换的经典/量子模型和查询损失单列，不自动继承底层 QROM/NIST 等级到完整 IBS 或 IBME。

## 4. 文件与第一批（2026-10-12；2026-10-18 已完成）

拟新增 `src/ibme/hibe/latte/`、`lai/`，认证转换核心/ML-DSA/Falcon 适配独立目录，Xie 独立研究/后端；具体路径先认领。NTRU/FFT/外部 C 依赖封装、专属测试/参数及许可证材料归 C；共同导出、registry、协议和 CLI 归统筹。材料放 `docs/research/team-c-delivery/<批次>/`。

第一批交 LATTE/Lai 资格对照表、已知采样问题复验与拟修差分、作者代码完整编译/两层运行入口和环境成本；同步交认证转换可执行规格、底层库版本/许可、ML-DSA KAT 的实际收据。未执行写未执行；不以零失败样本推安全。

第二批交选定结构 HIBE 或完整转换 IBS 的共同契约、严格对象/参数/绑定/恢复、真实生命周期，以及登记/容量提案。由统筹逐个与已就绪伙伴组装，C 不另写 IBME。若 C1 适配不明，继续 C2 独立工作并记录匿名缺口；如果 Xie 原文冲突仍未解决，保留 C3 核验材料，不改造后冒充原稿复现。

代码/参数/测试/算法章节同批提交，含来源许可、环境、结果指纹和限制。当前配置未正式准入继续 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。Sage 使用 WSL `~/miniconda3/envs/sage`。

**完成情况（2026-10-18）**：两批均已交；LATTE、ML-DSA、Falcon 已进入默认框架并完成真实组合/安装恢复，Lai/Xie/Zhang 保留研究核验材料。下一批转入第 0 节列的匿名/模型/正式参数与统筹配对。
