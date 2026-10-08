# 2026-10-08 文献复核与实施规划交付

起点 `6fd7f42`。本轮已同步队友最新归档，重新调查 HIBE 和直接 IBS 候选，并按用户转述的老师建议，把安全理论交付重点调整为引用定理及算法/参数/实现对应。具体算法最终选择与正式后端为 **WIP**。

## 修改文件

- 新增 [文献复核与后续实施计划](../../research/2026-10-08-selection/文献复核与后续实施计划.md)与[核验记录](../../research/2026-10-08-selection/核验记录.json)。
- 更新 `docs/PROJECT_RESTART.md`、`IMPLEMENTATION_SPEC.md`、`papers/index.md`。
- 给 `docs/research/2026-09-30/IBME-HIBE候选方案筛选.md` 和 `docs/research/2026-10-08-integration/三组优先组合与联合优化路线.md` 增加后续复核说明，保留历史内容。
- 新增 `papers/survey-manifest-2026-10-08.json`。
- 新增五份固定原文：`2010_bonsai_trees_cash.pdf`、`2010_lattice_hibe_standard_agrawal.pdf`、`2024_quantum_safe_hibe_zhao.pdf`、`2020_ideal_lattice_hibe_zhang.pdf`、`2024_ibs_without_trapdoors_luo.pdf`。
- 本交付文件。

跨研究、进度、规范和论文目录是为了统一最新优先级及引用口径；没有修改密码接口、算法代码、生产参数、队友归档或冻结证明材料。

## 核验范围

本轮运行的命令包括 `git status --short`、`git log --oneline -5`、`git fetch origin`、`git merge --ff-only origin/main`、`git diff --check`；文献指纹与 Markdown 核验通过内联 Python 和 `pypdf` 执行，实际计数与结果见核验记录。

PDF 核验检查文件头、大小、页数和 SHA-256；文档核验检查代码围栏、数学围栏、本地链接和行尾空白。没有密码代码变更，未运行密码算法测试或性能基准；文档/文件检查不能替代安全证明。

SRGG 出版社原文经检索工具可读，但本地 PDF 下载返回 403；GKR/Sageloli 的全文缓存尝试也未成功。失败响应没有保存为 PDF，清单保留失败原因。使用现有 Python 的标准库获取文献，没有安装软件；不依赖 Sage。本轮没有最终失败的密码测试，因为未运行该类测试。

## 参数与安全声明

没有选定新的生产参数。文献参数、尺寸、安全估计和计时仅作为来源材料，尚未按统一目标复测；生产教学后端保持原有 `security_claim: none`。本轮没有提出整个 IBME 的标准模型、QROM 或 NIST 等级声明。

## 未完成内容和风险

- 首套算法需下一轮的模型、参数、接口对应后冻结；三组表格是研究任务建议，不是已完成实例或最优排名。
- Luo 2024 重复身份签名的模拟/缓存解释、SRGG 底层定理前提和尺寸表不一致需核验。
- Yu–Liu–Li 2026 全文仍缺；Latte 所需匿名性未完成直接定理对应；2020 环格 HIBE 的委派类型与参数条件存在实施疑点。
- 真实安全参数后端、旧公开伪造/篡改修复、完整评测、独立 Ring-SIS 完整实例和端到端组合优化尚未完成。
- 暂不继续默认补全 Foo–Li 的完整形式化或 QROM 归约；已有材料保留，不把尚有前提的结论改写为已证明安全。

本轮 Git 提交哈希与推送结果在交付回复中报告；修改内容全部纳入一个文献/实施规划任务提交。
