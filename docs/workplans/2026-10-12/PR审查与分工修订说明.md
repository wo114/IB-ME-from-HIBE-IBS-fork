# PR 审查与三人分工修订说明

日期：2026-10-12。用户要求先处理队友规范/路线/分工，再做 A 的实现目标。本次审查从远端私有仓库读取版本，修改在 PR #11 的隔离工作树；不覆盖主工作树的三个既有未跟踪论文/清单文件。本轮没有合并 PR。

> 2026-10-18 状态：本文是 10-12 的审查/修订记录（当时 PR #9—#11 未合并）。此后 PR #12—#38 已全部审查合入，最新主线为 `upstream/main` `4472775`；当前状态以 [PROJECT_STATUS](../../PROJECT_STATUS.md) 为准，本文的 PR 表不再表示未合并。

## 1. 远端版本与接收关系

| PR | 审查头 / 状态 | 内容与处理 |
|---|---|---|
| [#9 Luo](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/9) | `e5e0b97752f9291ce7621dd830d665baff86aef8`；非草稿 | C64B 参数 helper、Luo 恢复/验收与性能证据；分配 B1 接收。未包含在 #11，不能把外部收据当合并代码 |
| [#10 规范/目录](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/10) | `2868cf54411188562440820eba266ca3dd278fd9`；草稿 | 共同接口与专属规范分开、19 条目录、新 Lai/Xie 原文；已被 #11 继承，本轮在 #11 同步修订，不重复接收为两份新增 |
| [#11 装配/分工](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/11) | `f98de52f25e117fa7e365c686c23e0c142d004b1`；草稿 | registry/装配、独立参数选择、CLI/状态、组合 runner 与分工；本轮只修分工和现行文档，代码保持该头 |

主仓库基点为 `bc22c9cb834dee51e9c8b7a37040fa0c5349fcdb`。检查时三 PR 可自动合并且没有状态检查记录；MERGEABLE/CLEAN 只表示 Git 合并状态，不能代替代码与数学验收。

## 2. 保留哪些已有成果

“公共框架 + 独立原语 + 兼容装配”的方向符合用户构想：每个 HIBE/IBS 实现一次，通过公共接口复用，允许不同参数/困难假设。PR #11 的版本/格式/参数快照、能力/容量预检、严格选择与无 mock 兜底应保留，不另起一套协议。

PR #10 的目录区分全文/代码/组件/完整后端/模型对照，比固定三套名单完整。19 条是候选与模型路线，不是已实现算法或不同困难假设数。Lai/Xie 的原文和疑点材料应保留；原文取得不等于解决参数/委派/采样。

历史密码实验、旧教学攻击、外部交付与最终框架复跑应保留各自版本。Luo PR #9 的 C64B 声明有前提，仍 none/false；条件中止指数不能称安全位数。

## 3. 为什么原分工要修订

| 原问题 | 本次具体修订 |
|---|---|
| 根规范/状态把约 11 天写成用户截止，本文用户已要求时间充分 | 移除当前期限推定，采用 S0—S5 验收阶段；保留历史报告证据 |
| 一人一个新增主原语、预置三套，无法覆盖“各做若干方案、完整交叉” | A 矩阵 HIBE、B 原生 IBS、C 结构 HIBE/工程 IBS，各按族顺序交多方案；就绪池全部可行配对，最后三个只作报告重点 |
| LATTE 与 BNN-Falcon 过早固定为编码/代表主线 | LATTE/Lai 同批核验后选择；认证转换先 ML-DSA 再 Falcon，共用转换核心，定位工程对照；原生论文路线仍优先 |
| Foo–Li、Wang+PW、ABB-ROM、原生 NTRU/RSIS 等无明确完整顺序 | 全部 19 条给 owner/P0—P3、任务 ID、下一步/停止条件；复杂路线保留储备，不假定全能立即编码 |
| 公共工具、全矩阵、测试、图表、展示、报告和支撑收件欠明确 | T0—T10 指定统筹、依赖和实物；三人同批交算法章节/来源/数据，报告骨架/材料模板现在给出 |
| 模板“任务 A”容易与队员 A 混淆 | 通用模板注明类型不等于队员；具体以 A0/B1/C1/T0 等 ID 派发 |

选择次序依据：已有实物/可合法复用代码、原文算法和模型是否清楚、有限参数/资源是否可核、缺口是否可界定、能否供其它模块复用。不声称现在已经证明哪套最快/最安全，也不为覆盖困难假设把 IBE 重命名 HIBE。

## 4. 本轮实际验证与未核范围

在 #11 `f98de52` 源码执行：

```text
python -m pytest -p no:cacheprovider -q --tb=short tests/test_assembly.py tests/test_cli_selection.py tests/test_combination_matrix.py --junitxml=test-results/team-plan-review-assembly.xml
```

**结果：85 passed，3.79 s。** 环境 Windows，Python 3.14.6；这是本轮装配/选择/组合驱动定向回归，无跳过，不是此前 122 项的重述。原始 JUnit 归档为[assembly.junit.xml](assembly.junit.xml)。框架测试中有 mock、教学原语与已有研究配置，不能计为 85 个真实密码方案或新目标组合。

文档和任务登记另核 19 条覆盖、owner/优先级、依赖 DAG、当前入口一致性、本轮新增本地链接及 `git diff --check`。完整结果写[validation.json](validation.json)，其检查范围不扩展到未执行密码实验。

本轮没有重跑 Sage CHKP 大采样、PR #9 的全部实验、未知真实后端、完整参数估计或 QROM 安全证明。没有改 `src/`、`tests/`、`experiments/` 或冻结接口。没有新密码参数；现有研究声明保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。

## 5. 合并前的剩余验收

修好的分工可供三人立即认领，但 #11 保持草稿，不在本轮直接合并。T0 仍须把代码审查/版本整合与本轮文档修订分开：核共享 CLI/状态恢复/兼容边界、#9 helper 与最新 registry 的真实接线；选择所受影响的契约和实际组合重跑，再形成合并结论。没有失败证据时不无限重复测试，也不能用干净 diff 替代接口审查。

#10 与 #11 的接收顺序须按包含关系处理，#9 单独归 B1；任一分支又有新提交时重新固定版本并核差分。A/B/C 可准备不依赖未合并共用入口的原文、单体和工具，不复制公共协议。本轮之后再开始用户的 A 实现任务，不用实现目标盖过分工/统筹的当前要求。

可直接使用：[总计划](../三人方案分工与统一框架交付.md)、[A](A-矩阵HIBE任务.md)、[B](B-原生格IBS任务.md)、[C](C-结构HIBE与工程IBS任务.md)、[统筹/报告/材料模板](统筹-接入评测与作品交付.md)、[任务登记](tasks.json)。

## 6. 本次修改文件清单

全部属于同一分工/审查任务边界，未修改密码代码：

- 当前规范入口：`AGENTS.md`、`AI_WORKFLOW.md`、`ARCHITECTURE.md`、`DELEGATION_PROMPTS.md`。
- 当前目录/状态：`docs/ALGORITHM_CATALOG.md`、`docs/PROJECT_STATUS.md`。
- 计划：`docs/workplans/三人方案分工与统一框架交付.md`、`docs/workplans/2026-10-11/可选原语平台与参数性能展示目标.md`。
- 新增任务包（均在 `docs/workplans/2026-10-12/`）：`A-矩阵HIBE任务.md`、`B-原生格IBS任务.md`、`C-结构HIBE与工程IBS任务.md`、`统筹-接入评测与作品交付.md`、`PR审查与分工修订说明.md`、`tasks.json`、`validation.json`、`assembly.junit.xml`。

提交信息为 `docs(plan): clarify multi-scheme team ownership and full combination delivery`，具体提交哈希以 PR #11 更新提交和最终交付消息为准，避免文档自引用提交哈希。
