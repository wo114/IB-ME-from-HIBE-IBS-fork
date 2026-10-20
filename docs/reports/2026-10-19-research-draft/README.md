# 研究报告初稿

## 当前编辑入口

2026-10-20 起以 **LaTeX 源稿 → PDF** 为唯一当前编辑链。直接编辑[LaTeX源文件](研究报告初稿.tex)，使用[PDF](研究报告初稿.pdf)阅读；[build_pdf.py](build_pdf.py)直接编译源稿，不经过Word。已有Markdown、Word、`build_report.py`和`validation.json`是PR66固定版本的历史材料，不再与当前正文同步。

当前正文已同步冻结的三代表：A为LATTE-3＋BNN/ML-DSA-44，B为LATTE-3＋SRGG PARAM-I compact，C为Lai C2＋Sageloli RSIS v3 PARAM-I。旧LATTE＋ML-DSA／Falcon／Luo重复数据仅作辅助工程基线。七章正文、11张表、6幅图和15项文献已更新为这一口径，A、B、C各自保留实际参数、样本结构、环境和限制，不做跨环境速度排名。三组精确profile按项目决定为`project-admitted/true/true`；这不等同于完整IB-ME获得外部NIST认证。

## 当前竞赛版式

当前版式以仓库保存的[2026年第十一届复赛官方模板及指纹](../../competition/2026/README.md)为权威基线，2025年优秀作品只作为内容组织的次级参考。现稿采用官方A4页面和四边20mm页边距，正文页眉固定为“全国密码技术竞赛作品设计报告”，页脚只显示页码；继续保留“赛事封面—基本信息表—目录—图表目录—正文”的可读结构、宋体正文、黑体标题、首行缩进、章内图表编号和书刊式三线表。官方模板给出的一级、二级标题本身注明可按作品实际情况增删，因此正文继续使用本项目七章结构。

当前封面把作品类别标为软件设计，作品编号由单一`\worknumber`宏控制，并在封面和基本信息表复用；工作稿保持空值，赛事系统分配编号后只需填写一次。封面标志已替换为官方模板内嵌JPEG的逐字节副本[figures/cacr-logo.jpg](figures/cacr-logo.jpg)，SHA-256为`908993f5ce1186b588114ea4a2f30e88691dbf1e7aef9b43a1b7080ff1324b4e`。公开证据索引不再嵌入带仓库账号的GitHub链接，而改用支撑材料根目录下可核对的相对路径。

当前仍是工作稿。远端合入或在途的B、C安装／负例／边界证据需在审定后按同一Suite增量同步；成稿还需完成来源许可、同一发布版本复现及最终匿名复核。提交前必须填写系统作品编号，按官方名称分别准备设计报告PDF、支撑材料和审批及签字页；签字页不并入匿名设计报告。

编译需要Tectonic或带中文支持的XeLaTeX，使用TeX发行版的Fandol字体，不绑定Windows、某一Sage环境或本机字体路径。在仓库根执行：

```text
python3 docs/reports/2026-10-19-research-draft/check_latex_report.py
python3 docs/reports/2026-10-19-research-draft/build_pdf.py
python3 docs/reports/2026-10-19-research-draft/check_latex_report.py --require-pdf
```

也可用`--engine /路径/tectonic`指定引擎。图像使用同目录的`figures/`，所有辅助文件生成在临时目录，成功后才替换PDF。`check_latex_report.py`从冻结`selection.json`复核代表ID、准入、参数、容量、时间、尺寸、章节、图表交叉引用和竞赛版式标记，并逐文件校验两份官方DOCX和官方标志的字节数及SHA-256。普通工作稿允许作品编号留空；`--submission-ready`会额外要求编号已填并检查当前PDF。当前`--require-pdf`为144项通过；编号尚空时，`--submission-ready`应且只应在编号门槛失败。自动检查和功能测试都不替代PDF逐页目视、身份信息人工复核或密码学安全证明。原PR66／68的格式迁移记录仍见[接收记录](../../deliveries/2026-10-20-pr66-68-reception/README.md)。

当前成品已用Tectonic 0.17.0重编：30页A4，其中封面和基本信息表2页、罗马数字前置页4页、阿拉伯数字正文及附录／文献24页；20种字体全部嵌入。源稿与PDF的SHA-256分别为`998ac7a54aa8897cafb2aa395a6faad0305911968648a6f479f62264439765e2`和`68570bb58839ae9d7fbadaf28454276e4c3018bfddb67cebe3d4de5ccf2eed99`。最终30页已按五组接触表并对封面、基本信息表、正文首页、证据索引和参考文献单页放大检查，未见截断、重叠、空白孤页、单句孤页或缺字；证据路径换行可读。Poppler文本抽取无Unicode替换字符和已知匿名禁词，PDF元数据没有作者字段。最终编译日志无LaTeX溢出、缺字、未定义引用或版面警告。

## PR66历史稿说明

日期：2026-10-19。根据用户要求另建研究报告，保留旧作品报告，暂不制作或更新PPT。本批只有文档、插图、文档构建与复核工具及当前进度入口；不修改原语、协议、参数或演示程序，不生成新密钥。

历史[Word](研究报告初稿.docx)及[Markdown正文](研究报告初稿.md)按PR66保留。Word沿用A4、宋体正文、黑体标题排版。原v0.1曾渲染并检查25页；本次PR66修订版已重建为11张表，但尚未产生新版Word页图，不继承旧版版式验收。下文版式诊断和页序均指历史Word，不能当作新PDF的结果。

## 内容与依据

| 部分 | 原v0.1页序（修订版未确认） | 已填内容 |
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

原稿代码说明基点为`b92967b92a94a4f8e18ae177ea299167b60aac67`；本次表3直接读取main `6f04f2b`所含E13参数JSON，原三组系统统计仍沿用各自固定来源。不同历史实验仍保留各自采集时的源码和环境：三组完整基线使用Core Ultra9 275HX，SRGG单体使用Core Ultra7 255HX；部署消融固定`3ae9826`及同一wheel三路对照。报告不把本次文档整理记为新实验，也不合并不同批次密文范围或RSS口径。

## 图表与复核

[report-facts.json](report-facts.json)保留四份输入JSON的SHA、三组完整Suite、样本数、中位数及Foo–Li选定参数原始行。表3按q=2^127−1、g=16、各n最小m̄从E13生成；表5、表6、表7及图4、图5从原统计JSON生成，不手工重抄。图6只裁取已有公开演示图的加密与正确匹配区域；原图与日期在正文、E12中说明，内容未修改。

在仓库根目录运行：

```text
python docs/reports/2026-10-19-research-draft/check_report.py
```

本次修订结果为**197项通过**，收据见[validation.json](validation.json)。检查内容包括公开源指纹、从逐次观察重算中位数与次数、表格数字、Word与Markdown十一张表逐格一致、Foo–Li三行与原JSON和维度公式对应、章节/文献/图片、链接存在，以及旧报告和PPT指纹未变。该检查是文档一致性检查，不是密码学安全证明或新的原语测试。

原v0.1使用文档技能的`render_docx.py`经LibreOffice渲染，检查全部25页PNG后修订：去掉默认标题蓝线、处理尾部孤页、整表跨页问题和截图可读性。最终修订只有图2文字宽度变化；与前轮25页逐像素比较，仅第8页不同，该页重新目视检查，其余24页完全相同。渲染PDF、PNG和参考提取文本只保留在本机QA目录，不随成果提交。

本次修订修正390208→390160、有限网格和模型搜索下限措辞，并将不同安全目标和尺寸口径的对象数字限定为资源示例。新增5项来源绑定回归，在规定WSL Sage环境执行`python -m pytest -q tests/test_report_fooli_bindings.py`，5 passed、0 skipped；测试已加入portable framework CI。

本次重新调用页面渲染器时返回`FileNotFoundError: LibreOffice soffice.exe was not found on PATH`。按文档技能的逐页检查要求，本修订版**尚未完成版式验收**；不能把197项结构检查、旧25页检查或CI成功替代为新版渲染通过。Word、Markdown和validation已同步，可在具备对应渲染运行时的环境继续核验。页面数、断页和表格可读性均不由本批认证。

重建需先在项目规定的WSL Sage环境执行以下绘图步骤，再用有python-docx、Pillow的文档运行时生成Word；图中中文使用Windows微软雅黑字体，当前构建针对Windows加WSL环境：

```text
python docs/reports/2026-10-19-research-draft/build_report.py --figures-only
python docs/reports/2026-10-19-research-draft/build_report.py
python docs/reports/2026-10-19-research-draft/check_report.py --record
```

第一条需matplotlib及Pillow，本批在`~/miniconda3/envs/sage`执行；后两条在Codex已配置的文档Python运行时执行。重建后需重新渲染检查，页数和文件指纹可能随编辑器、字体及打包元数据变化。验证器会比对本批保存的原始参考字节；换行转换引起的源指纹变化也应先核对，不能直接跳过。

## 本批文件与边界

新增正文、Word、此说明，`build_report.py`、`check_report.py`、`report-facts.json`、`validation.json`及`figures/`下6张图；只在`docs/PROJECT_STATUS.md`顶部增加当前入口和用户决定。旧`docs/IBME_作品报告.md`、`docs/COMPETITION_DEMO_AND_DEFENSE.md`与`ib-me.pptx`未修改。

旧作品报告SHA-256仍为`d3ae98a1cd4699b2be3cd8474f8607ae5415f0bfb60d83530b3f8f8679040957`，PPT仍为`c1bd68722c4f2fee16f86a3ad8343a36b6223c0d07b3d9a27238b555c8dea4b4`。在PR66固定时，最终三代表、必要消息长度补测、来源许可、本届模板与匿名信息尚未完成，相关组合当时也仍保留`none/false/false`。这些是历史版本边界，不覆盖本页顶部记录的当前三代表及项目准入状态。
