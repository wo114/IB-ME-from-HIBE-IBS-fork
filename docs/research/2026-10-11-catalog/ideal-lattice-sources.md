# 理想格陷门论文：来源、获取结果与作者代码核验

核验日期：2026-10-11。范围：指定论文的合法全文获取与作者公开代码检索；未执行外部代码，未完成全文精读或证明审查。

## 1. 身份与阅读入口

- **题名**：Trapdoors for Ideal Lattices with Applications。
- **作者**：Russell W. F. Lai、Henry K. F. Cheung、Sherman S. M. Chow。
- **年份**：Inscrypt 2014 会议；2015 年正式出版，LNCS 8957，239–256 页。不能记成 2018 年论文。
- **DOI**：[10.1007/978-3-319-16745-9_14](https://link.springer.com/chapter/10.1007/978-3-319-16745-9_14)。
- **作者确认**：[Cheung 的论文目录](https://sites.google.com/view/kfcheung/research)、[CUHK 课题组目录](https://crypto.ie.cuhk.edu.hk/theory/)。
- **可读版本**：[Chow 的 Academia 论文目录](https://cuhk.academia.edu/ShermanSMChow/Papers)链接到[作者上传的文章页面](https://www.academia.edu/87100350/Trapdoors_for_Ideal_Lattices_with_Applications)。

## 2. 获取结果：网页可读，原始 PDF 未取得

已由网页工具实际取得该文章页面的全部 95 条抽取文本行（L0–L94，无缺失行），包含正文至原文第 18 页的页码及 22 条参考文献。这个检查只说明网页抽取范围覆盖完整；数学公式存在抽取损坏风险，不能替代原 PDF 的逐页验收。

**本次没有生成 PDF 文件，也没有把网页正文重新打包冒充 PDF 或完整原稿。** 下列访问结果支持降级记录：

| 来源 | 本次结果 |
|---|---|
| Springer | 身份与出版信息可读；显示订阅预览，未取得 PDF |
| 原作者旧站 `home.ie.cuhk.edu.hk/~lwf014/hibe.pdf` | HTTP 403 |
| CiteSeerX 新旧 PDF 地址 | 网页工具 403；直接访问 404 |
| Wayback availability 对原作者 PDF 地址 | `archived_snapshots={}` |
| 作者 Academia 上传页 | 网页工具可读正文；直接下载网页触发 403，停止该路径 |

详细地址、缺失资产及工具边界见[独立获取记录](../../../papers/ideal-lattice-fetch-2026-10-11.json)。未安装抓取器、未登录或绕过访问控制。paper-fetch 工具与 CLI 不可用，故采用窄范围独立来源核验；该 JSON 不是伪造的 paper-fetch 工具输出。

## 3. 候选适配边界

以下是选读结论，均属于**论文作者的论述或本轮工程待办**，不是项目已有实现：

- 原文 §2.2、§5.1–5.2、定理 10 使用 PLWE 并宣称 INDr-ID-CCA，文中解释 INDr 包含接收者匿名性。
- §5.2 展开基本 IBE，称 HIBE 的 Derive 沿用 Extract；本项目仍需补齐两层算法及模型映射。
- §3.3、§4.4–4.5 给出环采样、委派与符号参数条件；未核准可直接运行的具体安全参数。
- 原文涉及标签逆元；实现前应核查标签取值域、采样条件及噪声界。网页公式不能作为最终实现依据。

来源：[作者上传版本](https://www.academia.edu/87100350/Trapdoors_for_Ideal_Lattices_with_Applications)。本轮不据此认定标准模型/QROM 的组合结论，不宣称与共享 IB-ME 框架已经兼容。

## 4. 作者公开代码检索

### 已确认的作者仓库

[作者当前主页](https://russell-lai.hk/)与[GitHub 账号](https://github.com/russell-lai)相互对应。已取得该账号的 7 个公开仓库清单，并检查最相关的 [lattice_lib](https://github.com/russell-lai/lattice_lib)。

| 项目 | 核验值 |
|---|---|
| 固定提交 | `7ea94e102bc107b1f037e30f07f539d694a6d569` |
| README 定位 | 圆分环上的 SageMath 格密码通用工具 |
| README 环境 | SageMath 10.9 |
| 许可证 | LGPL-3.0-or-later |
| 树清单 | 完整返回，`truncated=false` |
| 主要模块 | `util`、`conductor_analyser`、`geometric_norms`、`subtractive_set`、`twisted_trace`、`circulant_rep` |
| 本轮执行 | 未安装、未运行 |

固定版本：[README](https://github.com/russell-lai/lattice_lib/blob/7ea94e102bc107b1f037e30f07f539d694a6d569/README.md)、[源树](https://github.com/russell-lai/lattice_lib/tree/7ea94e102bc107b1f037e30f07f539d694a6d569)、[许可证](https://github.com/russell-lai/lattice_lib/blob/7ea94e102bc107b1f037e30f07f539d694a6d569/LICENSE)。

已查模块列表与 README 未显示本文完整 HIBE 或 `ringGenTrap/ringSampleD/ringDelTrap` 实现；未逐个审计所有函数，因此这属于仓库结构核验，不是全库功能证明。作者[资源页](https://russell-lai.hk/resources/)的代码链接亦不能当作本文实现。

### 检索结论

精确题名、作者姓名、作者网站、GitHub 公开仓库及环陷门算法名检索后，**截至本次已查来源，未确认作者提供的本文完整 HIBE 代码或具体参数包**。GitHub 精确题名仓库搜索返回 0 条，只是本次检索结果，不能证明不存在其他公开实现。

仓库外保存了原始 GitHub 元数据、固定版本 README 与许可证，位于：

`C:/Users/A/.dsh/deliverables/ideal-lattice-source-audit-2026-10-11/`

逐文件 SHA-256 见获取记录。该目录没有算法运行产物，也没有本文 PDF。当前可把此论文列为具匿名性论述的环格 HIBE 文献候选；不能列为“已有作者代码、参数可直接复现”的后端。
