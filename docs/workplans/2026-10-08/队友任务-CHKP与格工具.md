# 队友任务书：CHKP 两层匿名 HIBE 与格工具

日期：2026-10-08。可直接把本文件交给负责 HIBE 的队友或其 AI。任务是在已确认 Wang HIBE + IBS 组合下，实现 **CHKP/Bonsai Trees §5.3 的两层匿名 ROM HIBE**；不负责 IBS、协议包装或另一个 IBE + IBS 通用协议，不恢复增强隐私。

## 1. 开工依据

先取得含本任务书的最新 `origin/main`，执行仓库要求的 `git status --short` 和 `git log --oneline -5`。旧 `task/*` 分支是早期版本，不能把它们当作最新实施基线。可在自己的 fork/分支工作；使用 `codex/chkp-hibe` 等明确分支名，不整体覆盖主仓库文件夹。

必须阅读：

- [AGENTS.md](../../../AGENTS.md)、[架构](../../../ARCHITECTURE.md)、[唯一接口规范](../../../IMPLEMENTATION_SPEC.md)、[协作工作流](../../../AI_WORKFLOW.md)、[分工提示](../../../DELEGATION_PROMPTS.md)。
- [R1 HIBE 规格](../../research/2026-10-08-r1/两套HIBE实施规格.md)和[R1 首套/参数记录](../../research/2026-10-08-r1/README.md)。
- [36 页 CHKP 原文](../../../papers/2010_bonsai_trees_cash.pdf)：§3 的格基工具、§5.1、§5.2、§5.3、Theorem 5.2。文件指纹已归档。
- `src/ibme/hibe/api.py` 和现有 HIBE contract tests。现有 `abb10.py` 是旧教学实现，不能照抄后改名为 CHKP。

理论材料采用算法/定理/参数/实现对应表，不要求重新证明基础定理或做 Lean 形式化。真实采样、维度、合法条件和工程验证仍须完成。

## 2. 允许修改的文件

| 范围 | 建议文件 |
|---|---|
| 独立数学参考 | `experiments/research/chkp_*` |
| CHKP 后端与配置 | 新增 `src/ibme/hibe/chkp.py`、`src/ibme/hibe/chkp_params.py`，及确有必要的对应 HIBE 导出 |
| 新格工具 | 新增 `src/ibme/lattice/basis.py`、`src/ibme/lattice/basis_sampling.py` 或先放研究目录的对应文件 |
| 单体测试 | `tests/test_chkp_*`、`tests/test_basis_*`，必要时 HIBE contract tests 中仅添加 CHKP 参数化入口 |
| 参数、原文映射和测量 | `docs/research/team-chkp/`、`experiments/chkp_*`、专用 CHKP 参数样例 |

HIBE + 格工具属于跨边界任务，因为 CHKP 需要完整整数格基扩展/随机化和真实高斯原像；交付中说明这项原因。**不修改** `src/ibme/core/`、`src/ibme/ibs/`、`src/ibme/protocol/`、CLI、全局 `Params` 或主 AI 的任务/总进度文档。新参数类型或共享格式有冲突时，报告具体差异，由主 AI统一补充规范。

## 3. 逐轮实施与验收

| 轮次 | 做什么 | 交付/验收 |
|---|---|---|
| **T1：完整基与扩展** | 根、一级和二级模矩阵；完整核格基；ExtBasis；清晰的对象/参数模型 | 检查 $A_tS_t=0\bmod q$、整数满秩、行列式 $q^n$；指出哪些参数只是代数例子；提交算法映射与测试 |
| T2：真实随机化与原像采样 | 合格 GenBasis、RandBasis、SampleD；核对宽度约定、父基消除、范数/噪声条件 | 实际生成和两次委派、每级解封装关系、采样统计及资源；不只测试方程，不用均匀数冒充 Gaussian |
| T3：两层 HIBE 全生命周期 | Setup/Extract/Derive/bit Encaps/Decaps；持久解封装原像缓存；真实序列化 | 同一地址重复取钥/派生和恢复的一致性、容量/输入/上下文检查；形成独立真实单体实例 |
| T4：字节适配与契约交接 | 按主 AI冻结格式接字节载荷，保留独立 bit 与文献多比特路线；匿名填充 | HIBE contract tests、小消息/空消息 framing、错误身份/畸形密文、规范加载、密钥/密文尺寸及耗时；给主 AI 集成 |
| T5：对照与性能支援 | 在首套稳定后，按新任务再做 ABB10 固定维度真实对照，或优化 CHKP 采样/缓存 | 独立任务边界、相同条件测量、不得靠删条件提高速度；T1 开工时不要一并启动 T5 |

需要 Sage 时，一律使用 WSL `~/miniconda3/envs/sage`，不在脚本中写死用户名路径。若该环境/依赖不可用，先交已完成数学对象和证据，不用假后端充当真实原语。

## 4. 算法与状态不能改错

- 身份顺序固定 `parent_id=rcv`、`child_id=phi`。根/父/子列数 $m,2m,3m$；CHKP 通过拼接扩展矩阵，不能套用 ABB10 的固定维度身份乘积。
- 一级密钥必须能委派，保存完整整数基；短解封装向量不具有这个能力。格基不先约模，序列化保留符号和完整维度。
- ExtBasis 后实施 RandBasis，不能把父秘密基直接作为子密钥的可见子块。
- 两个公开随机预言机分别生成矩阵块 $H$ 和 syndrome $G$，用途、前缀、身份路径采用唯一长度前缀编码。哈希输出由真实算法定义；模拟器的隐藏陷门不可变成公开身份算法。
- PDF 第 22 页要求重复身份保持同一解封装向量。真实随机源、测试固定流和私有缓存分开；序列化恢复缓存。不能每次 decrypt 偷偷重抽一个新用户密钥来回避该条件。
- 多比特路线需每位独立 syndrome/原像；共享前导按 §5.1/5.2 的具体描述，不能额外复用噪声或删掉位绑定。报告密文和私钥/公共扩展/缓存成本，不能只报最小数字。
- 原始 KEM 解码不保证错误身份或全部篡改自动输出 BOTTOM；不能在密文中加入公开身份来通过合同。T4 的受保护 framing/匹配失败由主 AI与队友先冻结，完整密文字节认证由主 AI负责。
- 不把 ROM 引用写成标准模型/QROM，也不把有限成功样本写成安全证明。合法选参未完成时所有新对象、参数/报告保持 `security_claim: none`。

## 5. 交接材料

每轮提交自己的文件，附：提交哈希/说明；精确文件列表；可重跑命令；实际通过、失败、中止和未运行项；所有参数及来源；完整 Gram-Schmidt/范数/误差条件对应；密钥和签名/密文以外的资源记录；WIP 和已知限制。

不传主私钥或演示 `*-state` 文件夹，不把固定测试密钥混作正式密钥。多台机器通过 PR 或 git bundle 合并；不要互传覆盖整个目录。共享目录中的同一个文件同一时刻只由一人修改。

T3/T4 完成后提交 PR，由主 AI检查并集成；不要修改基线协议内部以绕过尚未通过的 HIBE 契约。用户允许主 AI直接合并通过审阅的 PR，队友仍应提供可审查差异和验证记录。
