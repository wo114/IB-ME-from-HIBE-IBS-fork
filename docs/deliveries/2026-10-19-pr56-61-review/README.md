# PR56—61 审查与接收记录

2026-10-19。接收主仓库 `youzi258/IB-ME-from-HIBE-IBS` 的本批开放PR；用户随后明确要求关闭PR57。操作后的主线为 `85b87fa63d8183ceafdfd5dcac8c2147cabbdc7b`。本记录只归档源码审查、有限本地回归、原公开证据核验及实际合并/关闭操作，不把作者历史运行写为本机重跑。

## 实际处理

| PR | 交付与处理 | 最终版本 |
|---|---|---|
| [56](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/56) | 独立研究报告初稿，合并；旧作品报告/PPT保留 | head `0041b3a` → main `18cae94` |
| [57](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/57) | 旧Sageloli v2小参数的registry/CLI/LATTE接入，按用户要求关闭，未合并；原分支/提交保留 | head `922a900`，CLOSED |
| [58](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/58) | SRGG三档论文参数、两种格式、六组LATTE完整组合及PARAM-I重复基准，合并；与PR56的状态说明冲突已保留双方内容 | 原head `e23ab4f`，整合head `6acc18f` → main `bc8ccb5` |
| [59](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/59) | Sageloli环原生v3、两档论文规模实跑与恢复，合并；最新补件未改变算法核 | 算法 `32d0c0b`，head `293482a` → main `798226a` |
| [60](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/60) | Lai完整两级HIBE、公共接入和显式C2配置；补参数边界拒绝并整合最新主线后合并 | 原head `2180286`，修复 `7b13fe9`，整合head `0dd9548` → main `eadb878` |
| [61](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/61) | 新交付固定版本就绪核对材料，合并；原采集时的OPEN字段和另一台机器78项复验按历史保留 | head `9c29086` → main `85b87fa` |

完整Git哈希、远端操作时间与CI采集状态见 [review.json](review.json)。PR58的实现和原实验也是本线程此前完成，复核不冒称另一个人的独立密码学安全评审。本轮没有启动子智能体。

## 发现与修复

Lai原参数对象在模数范围检查之前执行试除法素性检查，解析异常uint64时可能长时间计算；此外任意正采样宽度可被wire静默舍入/溢出，消息容量也可超过实际一字节长度域。新增前置范围、精确六位小数往返和255字节上限，保持默认A点、C2及算法/采样不变。新19项边界测试已被现有Lai CI通配符覆盖。详见[红绿测试和参数修复补记](../../research/team-c-delivery/2026-10-19-lai-publication/INTEGRATION-REVIEW.md)。共享registry合并同时保留Lai与SRGG论文入口。

PR57与PR59针对不同实现代际，并非相同代码：前者是旧v2小参数接入，后者是v3环原生论文参数单体。PR57仍有CI失败，审查识别到无Sage发现路径提前导入采样器，以及LATTE配对测试依赖未构建原生引擎等原因；用户选择关闭后未继续修改该分支。后续直接为v3做公共接入，不把旧v2的TB级展开投影套在已实跑的v3上，也不把关闭的PR57配对写成main已支持。

SRGG与Lai原审计将共享源码绑定到各自冻结快照；主线有效整合后源码自然变化。校验器增加显式 `--historical`，分别从固定Git `7573014`、`2180286`核对原摘要；默认仍严格比较当前源码，原收据/摘要/JUnit均未重写。SRGG的provider摘要篡改负例仍保留。Sageloli补充校验同样严格绑定旧CI源文件，当前main的 `ci/suites.json` 与 `src/ibme/assembly/catalog.py` 已因接入Lai/SRGG产生有效变更；该历史校验器及其自绑定manifest保持原样，本轮在独立导出的原发布源树中复核通过。历史校验通过不能表述为在新主线上重新生成过原来的大参数状态。

## 本机实际复验

硬件i9-14900HX；规定WSL conda Sage10.7/Python3.12.13，OMP4/OpenBLAS1；Windows Python3.14.0a5。以下JUnit只删除hostname并规范XML输出，保留各用例、时间和结果。不与PR61的Ultra9/Sage10.9或原Sageloli作者Ultra7/Sage10.9数据混排。

| 本轮运行 | 固定运行源码 | 结果与公开JUnit |
|---|---|---|
| Sageloli结构测试及native算术/生命周期/恢复，实际重新编译原生核 | `32d0c0b`；与最新PR59运行代码一致 | [35 passed](pr59-independent.xml)，0失败/skip |
| 原始Lai四个专属测试文件 | `2180286` | [57 passed](pr60-independent.xml)，0失败/skip |
| Lai四文件＋新增边界＋registry扩展契约＋SRGG论文登记 | 合并树运行内容，对应 `4c56e63` | [132 passed](lai-merged-sage.xml)，103.93秒，0失败/skip |
| Hybrid、CLI选择、CI目录及C登记公共层 | 同上，Windows | [130 passed](lai-merged-portable.xml)，118.91秒，0失败/skip |

原始Lai57项包含在后面的132项内，不能重复相加；四份公开JUnit按classname/name去重为297个条目，不含作者267/180项或PR61的78项。此数字只表示本记录覆盖的测试身份，不表示覆盖所有参数或完整安全验证。测试文件清单和37项选定运行/测试源码摘要均收入JSON；这些摘要不是运行时动态provider捕获。

另核对：研究报告178项事实/来源/Word一致性检查；SRGG六组204功能检查、6个重复基准根、1824条基准provider、154条安装provider及零熵恢复；Sageloli原/补充公开验证器；Lai原44项绑定及作者267项测试计数。它们是对既有公开执行证据的核对。报告DOCX摘要仍为 `b79b75206076da6538db93e4c3cb9a2a6b9d7dfff380d48231e2160fab634f20`，使用该同一文件原有的25页渲染逐页联系图复核并抽看完整页面；本机未重新渲染成功，不将历史渲染改称本轮新生成。

CI状态以JSON采集时为准：PR56/59/61对应检查已完成且没有失败（strict-security手动项按原配置skip）；PR58、修复后的PR60尚有运行中/排队项，不能称新head全绿。PR60原 `2180286` 的CI此前全部必跑项通过；这不替代修复后本地132/130项或新的远端CI。PR57存在失败且已关闭。重复的push/PR事件分别产生检查，CI数量不等于测试条目数。

## 复核入口与未完成范围

```text
python docs/deliveries/2026-10-19-pr56-61-review/verify.py
python docs/reports/2026-10-19-research-draft/check_report.py
python docs/research/2026-10-19-srgg-paper-latte/verify.py --historical
python docs/research/team-c-delivery/2026-10-19-lai-publication/verify_delivery.py --historical
```

Sageloli以下两条命令应在固定 `293482a` 的独立checkout或Git archive导出目录中执行；新主线直接执行第二条会因上述CI共享源码变化而拒绝，不能改写历史manifest来把它算成新主线证据：

```text
python docs/research/team-b-delivery/2026-10-19-sageloli-ring-target/verify.py
python docs/research/team-b-delivery/2026-10-19-sageloli-pr59-review/verify.py
```

本记录校验器读取冻结Git与公开JUnit，不实时查询GitHub。当前远端状态需另查，后续进度以 [PROJECT_STATUS.md](../../PROJECT_STATUS.md) 为准。

尚待Lai C2可移交逐次原始目标收据、Sageloli v3公共接入和首套真实HIBE完整配对，以及选用配置的统一评测/材料收口；SRGG PARAM-II/III重复完整系统基准不计完成。本轮未重跑Sageloli两档论文规模新建或Lai C2目标生命周期，未做新估计器计算、参数扫描或证明。按用户研发前提引用论文与工作假设，实际声明仍为none/false/false；不新增NIST等级。
