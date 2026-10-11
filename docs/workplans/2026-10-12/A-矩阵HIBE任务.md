# A：矩阵 HIBE 与陷门工具任务书

日期：2026-10-12。总责任和全队顺序以[总计划](../三人方案分工与统一框架交付.md)为准；任务 ID 见[tasks.json](tasks.json)。本轮先交计划，之后由用户负责的 A 开始实现。A 不再承担 Luo 或公共框架的重复编码。

## 1. 负责的路线与顺序

| ID | 结果 | 先复用 / 仍须完成 |
|---|---|---|
| A0 / P0 | CHKP/MP12 同一完整配置的条件与资源表，选研究执行输入 | `first_suite`、CHKP 交接；根/父/叶、宽度、噪声、种子容量必须用同组参数，不拼接不同配置的通过项 |
| A3 / P0 | 有消费者的矩阵 Gaussian、陷门和真实委派公共工具 | 已有有限 CSPRNG/GPV/DelTrap；发布接口、边界、误差和资源口径，移植时保持固定身份与中止语义 |
| A1 / P0 | 真正的两层公开 HIBEBackend 和对象/状态交接 | 真正 Extract→Derive，六个方法、Hybrid 绑定能力、严格 codec；论文 CHKP 和 MP12 变体分别命名/映射 |
| A2 / P1 | ABB10-ROM 论文忠实固定维度 HIBE，可与 A1 比较 | 原稿 BasisDel、SampleR、两层宽度；旧 `abb10.py` 保留教学负控，不改名充数 |
| AR / P3 | GKR、ABB 标准模型、CHKP 标准模型的储备说明 | 每项交模型差异、缺失模块、有限成本、重新启动条件；不是本批完整编码 |

A0、A3 与 A1 的对象/适配工作可并行；真实委派路径要等其工具输入域核准。A2 接 A3，复用共同工具，不要求等 A1 正式安全准入后才开始。

## 2. 开始前读什么

- [公共规范](../../../IMPLEMENTATION_SPEC.md)、[架构](../../../ARCHITECTURE.md)、[协作](../../../AI_WORKFLOW.md)、[HIBE API](../../../src/ibme/hibe/api.py)。
- [first_suite 专属契约](../../specs/first-suite-research.md)、[CHKP 交接](../../research/team-chkp/README.md)、[参数/资源筛查](../../research/2026-10-11-first-suite-compact/README.md)、[根与公开攻击](../../research/2026-10-11-first-suite-root/README.md)。
- [CHKP 原文](../../../papers/2010_bonsai_trees_cash.pdf) §5、[ABB10 固定维度原文](../../../papers/2010_lattice_basis_delegation_agrawal.pdf)及[原算法核验](../../research/2026-10-04/ABB10两层HIBE算法与参数规范.md)。

不是把实验核直接搬进公开后端：先核论文对象和实际实现对应，明确哪里改变了陷门/采样算法。新增机制引用其相应论文，不共享另一个后端的安全结论。

## 3. 文件边界

现有 `experiments/research/first_suite/`、`experiments/research/chkp_*.py` 由原 owner 逐一交接。拟新增 `src/ibme/hibe/chkp/`、`src/ibme/hibe/abb_rom/` 及其专属 tests/params；路径可在认领时调整，不能与正在写的同名文件重叠。

矩阵公共工具仅认领所需 `src/ibme/lattice/` 文件；`__init__.py`、API、registry、protocol、CLI 和共同 runner 归统筹修改。A 交登记提案和可公开读取对象，统筹负责接入。A 的材料放 `docs/research/team-a-delivery/<批次>/`，不另维护全队排序。

## 4. 第一批必须交的实物

1. **缺口表**：真实根、父委派、叶采样、256 目标/32 B seed、两层身份各 86 B、公开 codec/绑定/恢复逐项列出实际代码、证据提交、缺口。不得只报 n=1 成功率。
2. **同组条件表**：全参数、取整和分布约定、正确性/采样条件、失败预算、根/父/叶尺寸与进程资源。每行注明实测或估算；给可执行研究配置和目标配置的差异及第一阻塞。
3. **公开后端的最小纵向切片**：使用真实工具完成 setup→extract→derive→encrypt→decrypt，加严格对象往返。若真实路径受阻，可先交对象/适配及精确阻塞，不能用公开假陷门或教学后端填补。
4. **参数选择决定**：现有 n=1 公开恢复样例保留为负控；下一候选先做困难性/资源筛查，再投入大采样。正式配置太大时记录条件及成本，继续合法研究接线；不靠降低门槛得到安全结论。

第一批以“能否接入一条真实完整 HIBE 路径”和“同组配置是否可行”为结果。无新疑点时不重复增加样本、单独优化或补证明长文。

## 5. 完成与交接判据

- 六方法满足公共接口；HIBE 身份为 `(rcv, phi)`，有真实两层 Derive，公开密文不泄露身份标签。
- 用默认安全熵与固定测试熵分别验证；实际 DGS 的误差口径、范数/宽度和资源中止明确，不能均匀代采样。
- 对象维度、模数、版本、身份路径、公钥归属、截断/追加/非规范解析均检查；固定叶恢复和中止后行为有实际证据。
- 交 factory、完整参数读取规则、五类对象 decoders、`load_ciphertext`、容量/尺寸/状态/绑定元数据提案；最终字段与当前 `BackendSpec` 对照。
- 原语契约通过后交统筹用 Luo 做真实组合、身份错配、伪造/重签和字节攻击。raw CPA 正常容错不强改成数学层篡改拒绝。

Sage 使用 WSL `~/miniconda3/envs/sage`。每批按[交付规范](../../../AGENTS.md)提交代码、准确命令/结果、参数/环境、论文—条件—代码映射、已知失败和算法章节。未正式准入时保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。

GKR/标准模型储备不占首批编码；某配置不可行时交具体原因，A1 的公开接线、A2 的独立核验和其它队员工作继续。
