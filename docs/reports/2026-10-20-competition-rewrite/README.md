# 作品设计报告正文重写

这是当前报告编辑入口。正式编号为`CACR2026T4PMR7`，正文直接编辑[LaTeX源文件](作品设计报告.tex)，阅读[生成的PDF](作品设计报告.pdf)。旧的31页[LaTeX与PDF](../2026-10-19-research-draft/README.md)作为重写前审计快照保留，不在本目录覆盖；改写依据见[作品设计报告改进审核稿](../2026-10-20-revision-review/README.md)。

## 当前状态

状态为 **WIP：第一批正文重写完成，尚非提交候选版**。

本批完成：

- 写入正式作品编号，保留官方封面、基本信息表、A4页边距和页眉页脚；
- 新增中英文摘要与关键词；
- 将正文重排为七章，完整重写第1章的问题、工程缺口、范围、三项贡献、三代表定位和全文结构；
- 从新稿移除未完成路线、内部状态字段、逐轮验收语言及旧候选附录；
- 为协议、原语、优化、实验和展示章节建立可继续扩写的技术骨架，并迁入必要的已核实结论；
- 建立面向新稿的独立构建和检查入口，旧稿检查器不用于强迫保留已经删除的内容。

本批没有修改原语、协议代码、参数、安全元数据或历史实验，也没有运行新的密码学实验。三组仍为A（LATTE＋BNN/ML-DSA-44）、B（LATTE＋SRGG PARAM-I compact）和C（Lai C2＋Sageloli RSIS v3 PARAM-I）；已完成配置沿用当前安全说明。

## 构建与检查

在仓库根目录使用本机配置运行：

```text
git ibme-run python3 docs/reports/2026-10-20-competition-rewrite/check_report.py
git ibme-run python3 docs/reports/2026-10-20-competition-rewrite/build_pdf.py
git ibme-run python3 docs/reports/2026-10-20-competition-rewrite/check_report.py --require-pdf
```

`--submission-ready`在第一批必须失败并指出尚有五批内容、实验、展示和发布工作；不能因为PDF能编译就把它标为最终稿。

## 后续批次

1. 展开两层路径、Hybrid、BYTEAUTH及五个核心原语的公式、对象形状、采样与委派过程。
2. 完成Sageloli、SRGG、Lai会话和部署消融的方法图、成本模型及结果分析。
3. 重建完整实验章和图表；在最终采用前同步未合并优化数据的审查结论。
4. 视预算补C的3924 B诚实往返与有限独立根；若不补则保持明确限制。
5. 使用最终三代表界面生成真实截图，并完成同版本安装与恢复展示。
6. 统一引文、来源、匿名和排版，逐页检查后才生成提交候选PDF。

报告正文不得出现Git提交、内部字段或开发往返；这些信息只保留在本说明、审核记录和支撑材料中。
