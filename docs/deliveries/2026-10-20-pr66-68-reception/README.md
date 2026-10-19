# PR66与PR68内容接收及LaTeX迁移

本轮对应用户批准的第1项：接收既有三代表选择和报告数值修订。用户另明确三组不要求共同达到128位，并改用LaTeX源稿、PDF交付。范围包含原交付审查、必要文档修订、格式迁移和PDF核验；后续补测与全文更新另行进行。

## 固定版本与接收范围

| 交付 | 固定版本与事实 | 接收边界 |
|---|---|---|
| PR68三代表 | 头`0d218d9e57b36a27406eecd60c533d0e72e52e7e`；远端已于2026-10-19合入`3b16cc1` | 接收A＝LATTE/ML-DSA-44、B＝LATTE/SRGG-I compact、C＝Lai C2/Sageloli RSIS v3 PARAM-I的配置和证据；不认定三者已分别赢得性能比较 |
| PR66报告修订 | 头`db086c70aa04764c663e7d7039b59767cc12fe94`，经`709b8e8`合入远端main，原提交历史保留 | 接收Foo-Li数值和来源绑定、有限网格与模型估计措辞；旧Word没有本轮页面核验，保留历史，不作为当前交付格式 |
| 新稿格式 | [直接编辑的LaTeX](../../reports/2026-10-19-research-draft/研究报告初稿.tex)、[导出PDF](../../reports/2026-10-19-research-draft/研究报告初稿.pdf)、[构建入口](../../reports/2026-10-19-research-draft/build_pdf.py) | 首次迁移保留七章、11表、6图、14项文献，明确历史基线与已选三代表的关系；仍是初稿，不是已完成全部收口的终稿 |

PR66原记录明确因缺少`soffice.exe`暂缓，原来的`record.json`、`render.json`和失败诊断没有被改成通过。此次依据用户更新的交付格式，接收内容并核验直接从LaTeX生成的PDF；不把PDF核验冒充Word核验，也不将其余正文欠项一并关闭。

## 实际核验

在仓库根运行，全部退出码为0：

```text
python -B docs/deliveries/2026-10-19-report-three-selection/verify.py --self-test
python -B docs/reports/2026-10-19-research-draft/check_report.py
python -B -O docs/deliveries/2026-10-19-pr66-report-revision/verify.py
PYTHONPATH=<临时pytest目录>:src:. PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONDONTWRITEBYTECODE=1 \
  python -B -m pytest -q -p no:cacheprovider --tb=short \
  tests/test_report_fooli_bindings.py tests/test_ci_catalog.py
python docs/reports/2026-10-19-research-draft/build_pdf.py --engine <tectonic路径>
```

- [三代表核对](selection.json)：59项检查通过、5个篡改负例拒绝；未在本机重跑装配和目标密码运算。
- [PR66文稿结构](pr66-structural.json)：197项通过，11张历史Word/Markdown表一致，Foo-Li三行与E13数据、维度公式对应。
- [历史诊断核对](pr66-history.json)：原Word失败门和固定输入绑定有效；输出的`hold_for_page_review`是原批结论。
- [本轮便携回归](portable.xml)：30 passed、0 failed、0 skipped，含5项来源绑定和25项CI清单测试；Linux/Python3.14.6/pytest9.1.1，临时依赖不改项目配置。
- [固定PR头远端CI](remote-checks.json)：两头各46 success、2 skipped，来自push/PR两组事件；跳过者均为手动`strict-security`，不按密码实验次数计数。
- [迁移一致性](latex-content.json)：11张表共281个单元格对应历史Markdown，保留7章、2个附录、6图和14项文献。
- [PDF核验](pdf-qa.json)：26页A4逐页目视通过，最终构建的110dpi页图与已审页面逐像素一致；15种字体均嵌入、41个书签、21个HTTPS证据链接，页面边界内未发现越界字符。编译无缺字、溢出或未定义引用警告，修订维度390160及图表/章节检查通过。pypdf不能正确提取本稿部分Fandol CID中文，文本内容核验采用Poppler；pypdf用于页数、尺寸、书签和链接。源文件与成品摘要由[接收清单](reception.json)绑定。页图仅作本机QA中间产物，不作为交付文件。

本机没有规定的`~/miniconda3/envs/sage`，未改用其它Sage运行算术。PDF由Tectonic0.17.0（XeTeX/LaTeX）直接编译；使用TeX Fandol中文字体、已归档六张PNG，Poppler渲染页面，Codex文档运行时Python读取PDF并检查内容。TeX引擎下载包SHA-256为`1a715688baf591e650c8aeb160ae934e181685eecbb38b317de30b269ac5d606`；临时引擎、编译缓存及页图不进Git。

## 参数和声明

三代表的原Suite、预算和源收据均未改：A的Hybrid载荷64KiB，B为128KiB，C为8MiB；外部身份64B、内层86B、seed32。引用性能数据仍为原32B应用消息批次。LATTE来源80bit、SRGG-I来源100bit及95/93bit量子成本按原文分别引用，不设共同128bit门，不为此改选PARAM-II。Lai/Sageloli的原模型、参数与采样限制保持。

ROM/QROM性质逐部件按原文引用，HIBE匿名性沿用用户已确认的工程工作前提，不新增基础证明任务。无新密钥、密码实验或安全估计；相关元数据仍为`security_claim=none / backend_admitted=false / parameters_are_formal=false`。文稿检查、CI和PDF编译均不构成安全证明。

## 后续未完成项

后续仍需围绕精确Suite补齐B安装CLI/wheel、C安装与有效外层下的内层负例、必要长度/边界及受预算约束的重复评测；代表的比较理由应对应实测，C不宣称已有性能优势。LaTeX正文需要同步较新接入状态、新三代表图表、来源许可、本届模板与匿名信息。旧Word版式未核验，旧报告及PPT未修改。

本轮跨`docs/reports/`、`docs/PROJECT_STATUS.md`与审计说明，是接收报告及遵照用户更改输出格式所需；不跨入原语或协议实现。PR66携带的`ci/suites.json`和5项测试作为已审交付接收，原提交历史保留。后续排序只在[项目状态](../../PROJECT_STATUS.md)维护。

## 本轮修改文件

- `docs/PROJECT_STATUS.md`：当前入口、用户格式决定和后续边界。
- `docs/reports/2026-10-19-research-draft/`：`研究报告初稿.tex`、`研究报告初稿.pdf`、`build_pdf.py`、`README.md`。
- `docs/research/2026-10-19-report-readiness/`：`README.md`、`audit.json`，撤回共同128位要求。
- 本目录：`README.md`、`reception.json`、`pdf-qa.json`、`latex-content.json`、`selection.json`、`pr66-structural.json`、`pr66-history.json`、`remote-checks.json`、`portable.xml`。

合计16个文件；完整路径及固定产物SHA-256见`reception.json`。这份记录只接收既有内容及完成格式迁移；初稿标为WIP的正文更新与实验欠项继续保留。

内容与PDF已由提交`19b6fba`（`docs(report): receive corrected draft and switch to LaTeX PDF`）推送远端main。GitHub REST API确认PR66和PR68均为`closed/merged=true`；PR66保留历史`draft=true`标志，不代表其未合并。合并提交、时间及固定头核对写入`reception.json`，本段为发布后的接收补记。
