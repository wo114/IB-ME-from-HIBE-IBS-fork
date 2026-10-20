# 作品设计报告正文重写

这是当前报告编辑入口。正式编号为`CACR2026T4PMR7`，正文直接编辑[LaTeX源文件](作品设计报告.tex)，阅读[生成的PDF](作品设计报告.pdf)。旧的31页[LaTeX与PDF](../2026-10-19-research-draft/README.md)作为重写前审计快照保留，不在本目录覆盖；改写依据见[作品设计报告改进审核稿](../2026-10-20-revision-review/README.md)。

## 当前状态

状态为 **WIP：前两批正文重写完成，尚非提交候选版**。

目前完成：

- 写入正式作品编号，保留官方封面、基本信息表、A4页边距和页眉页脚；
- 新增中英文摘要与关键词；
- 将正文重排为七章，完整重写第1章的问题、工程缺口、范围、三项贡献、三代表定位和全文结构；
- 完整展开第2章的Wang五算法、两层身份路径、Hybrid、BYTEAUTH、解密检查顺序、容量预检和状态恢复；
- 按统一的“论文关系—身份/消息映射—固定参数—实现差异”结构重写第3章，覆盖LATTE、Lai、BNN/ML-DSA、SRGG和Sageloli五个原语；
- 重写第4章的Sageloli结构化低秩采样、SRGG四类对象无损编码、Lai接收会话、有界准备复用及同参数部署消融，并明确收益与状态代价；
- 从新稿移除未完成路线、内部状态字段、逐轮验收语言及旧候选附录；
- 为实验和展示章节保留可继续扩写的技术骨架，并迁入必要的已核实结论；
- 建立面向新稿的独立构建和检查入口，旧稿检查器不用于强迫保留已经删除的内容。

这两批没有修改原语、协议代码、参数、安全元数据或历史实验，也没有运行新的密码学实验。三组仍为A（LATTE＋BNN/ML-DSA-44）、B（LATTE＋SRGG PARAM-I compact）和C（Lai C2＋Sageloli RSIS v3 PARAM-I）；已完成配置沿用当前安全说明。第4章采用已合并PR75的固定归档数据，并按实测、单根摊销和公式外推分别解释。

## 构建与检查

在仓库根目录使用Python 3运行；通过`--engine`指定本机Tectonic或XeLaTeX。`git ibme-run`只是原开发机别名，移交不依赖它：

```text
python3 docs/reports/2026-10-20-competition-rewrite/check_report.py
python3 docs/reports/2026-10-20-competition-rewrite/build_pdf.py
python3 docs/reports/2026-10-20-competition-rewrite/check_report.py --require-pdf
```

`--submission-ready`在当前阶段必须失败并指出只完成前两批；不能因为PDF能编译就把它标为最终稿。

## 后续四批

1. 重建完整实验章和图表；PR75已合并，按固定归档数据和成本边界整合。
2. 视预算补C的3924 B诚实往返与有限独立根；若不补则保持明确限制。
3. 使用真实A/B页面及C的实际执行入口整理演示，并完成同版本安装与恢复展示。
4. 统一引文、来源、匿名和排版，逐页检查后才生成提交候选PDF。

报告正文不得出现Git提交、内部字段或开发往返；这些信息只保留在本说明、审核记录和支撑材料中。

## 本轮接收修订

PR79修订已并入本稿：保留139/146 KiB、同机三位有效数字、进程内叶钥、实际引用及源稿/PDF摘要绑定。第2至4章展开协议、五个原语和四类优化；PR80审查进一步区分Lai新采样掩码与叶陷门、C的IBS消息容量和Hybrid空间，以及统一WSL环境中的部署位置消融。当前仍是前两批WIP；实验、展示、最终复现和提交检查尚待后续批次。

`build_pdf.py`生成[构建摘要](build-manifest.json)，`check_report.py --require-pdf`按源稿与PDF内容摘要判断对应关系，不依赖检出时间。`--submission-ready`仍必须明确失败，不把能编译的中间稿记为提交终稿。
