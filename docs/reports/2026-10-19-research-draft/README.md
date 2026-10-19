# 研究报告初稿

日期：2026-10-19。根据用户要求另建研究报告，保留旧作品报告，暂不制作或更新PPT。本批只有文档、插图、文档构建与复核工具及当前进度入口；不修改原语、协议、参数或演示程序，不生成新密钥。

优先阅读[可编辑Word](研究报告初稿.docx)或[Markdown正文](研究报告初稿.md)。Word按A4、宋体正文、黑体标题排版，已渲染并逐页检查25页。正文已有七章、6幅图、10张表、14项文献，属于可继续审阅的v0.1初稿，不是最终竞赛提交稿。目录先提供章节导航，最终模板适配时再生成带页码的正式目录。

## 内容与依据

| 部分 | 当前Word页序 | 已填内容 |
|---|---:|---|
| 封面摘要目录 | 1至3 | 实际题名、问题、方法、成果与边界 |
| 第1章 | 4至5 | 应用问题、自拟题目对应、研究内容 |
| 第2章 | 6至8 | 两层构造、五项操作伪代码、Hybrid与BYTEAUTH |
| 第3章 | 9至11 | 独立选参、三组实际配置、IBS现状与HIBE资源 |
| 第4章 | 12至14 | 模块契约、规范wire、固定发钥、持久状态与部署 |
| 第5章 | 15至19 | 三组完整基线、C64B、部署消融、SRGG单体编码 |
| 第6章 | 20至21 | 真实演示截图局部、贡献及对应证据 |
| 第7章 | 22 | 已完成结果与真实欠项 |
| 附录与文献 | 23至25 | 19条路线、12组证据入口、14项引用 |

沿用[先前写作标准](../../workplans/2026-10-18-作品报告规划与成稿清单.md)，重新核对用户提供的两份2025年PDF指纹、目录、方案和实验相关正文，并渲染查看8个参考页面。只借鉴问题与改动对应、先定义指标后展示结果等写法，不复制其中的实验数字、创新点、参赛编号或行业背景统计。两份参考PDF没有写入仓库。

代码说明基点为`b92967b92a94a4f8e18ae177ea299167b60aac67`。不同历史实验仍保留各自采集时的源码和环境：三组完整基线使用Core Ultra9 275HX，SRGG单体使用Core Ultra7 255HX；部署消融固定`3ae9826`及同一wheel三路对照。报告不把本次文档整理记为新实验，也不合并不同批次密文范围或RSS口径。

## 图表与复核

[report-facts.json](report-facts.json)保留三份输入JSON的SHA、三组完整Suite、样本数和中位数。表4、表5、表6及图4、图5由公开JSON生成，非手工重抄。图6只裁取已有公开演示图的加密与正确匹配区域；原图与日期在正文、E12中说明，内容未修改。

在仓库根目录运行：

```text
python docs/reports/2026-10-19-research-draft/check_report.py
```

本机结果为**178项通过**，收据见[validation.json](validation.json)。检查内容包括公开源指纹、从逐次观察重算中位数与次数、表格数字、Word与Markdown十张表逐格一致、章节/文献/图片、链接存在，以及旧报告和PPT指纹未变。该检查是文档一致性检查，不是密码学安全证明或新的原语测试。

Word使用文档技能的`render_docx.py`经LibreOffice渲染，检查全部25页PNG后修订：去掉默认标题蓝线、处理尾部孤页、整表跨页问题和截图可读性。最终修订只有图2文字宽度变化；与前轮25页逐像素比较，仅第8页不同，该页重新目视检查，其余24页完全相同。渲染PDF、PNG和参考提取文本只保留在本机QA目录，不随成果提交。

重建需先在项目规定的WSL Sage环境执行以下绘图步骤，再用有python-docx、Pillow的文档运行时生成Word；图中中文使用Windows微软雅黑字体，当前构建针对Windows加WSL环境：

```text
python docs/reports/2026-10-19-research-draft/build_report.py --figures-only
python docs/reports/2026-10-19-research-draft/build_report.py
python docs/reports/2026-10-19-research-draft/check_report.py --record
```

第一条需matplotlib及Pillow，本批在`~/miniconda3/envs/sage`执行；后两条在Codex已配置的文档Python运行时执行。重建后需重新渲染检查，页数和文件指纹可能随编辑器、字体及打包元数据变化。验证器会比对本批保存的原始参考字节；换行转换引起的源指纹变化也应先核对，不能直接跳过。

## 本批文件与边界

新增正文、Word、此说明，`build_report.py`、`check_report.py`、`report-facts.json`、`validation.json`及`figures/`下6张图；只在`docs/PROJECT_STATUS.md`顶部增加当前入口和用户决定。旧`docs/IBME_作品报告.md`、`docs/COMPETITION_DEMO_AND_DEFENSE.md`与`ib-me.pptx`未修改。

旧作品报告SHA-256仍为`d3ae98a1cd4699b2be3cd8474f8607ae5415f0bfb60d83530b3f8f8679040957`，PPT仍为`c1bd68722c4f2fee16f86a3ad8343a36b6223c0d07b3d9a27238b555c8dea4b4`。最终三代表选择、必要消息长度补测、来源与许可汇总、本届提交模板与匿名信息仍待完成。理论沿用原文引用及用户确认工作前提，实际参数和已知不安全调试档如实区别；所有相关组合的`none/false/false`安全元数据保持原样。
