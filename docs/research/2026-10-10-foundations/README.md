# 全候选基础包与三组代表的选择流程

日期：2026-10-10。起点 `a7e0482`，其 GitHub CI 两项均已成功；随后三篇用户 PDF 已单独提交并推送为 `683b0e3`（`docs(papers): archive user-provided GKR SRGG and Yu papers`）。没有新 PR。本轮响应用户的新安排：先给所有候选做基本工作，方便队友接手，再完成首套，最后按实际场景选择三组代表，其余方案保留为重要比较材料。暂停继续压缩/跑分，不预先认定 CHKP+Luo 或另外两套一定获选。

## 1. 已交付的基础与真实边界

已建立 **17个候选条目：7个HIBE、10个IBS**，见 [catalog.json](catalog.json)和[逐项基础卡与队友接手任务](候选基础卡与队友接手任务.md)。候选数包括矩阵/环实例、不同安全模型及两项认证转换储备，不是17套实现或17种困难假设。每张卡都有来源、算法/定理入口、接口/对象对应、实际后端/参数/模型状态、已有资产、三项接手任务和独立实验文件范围。

| HIBE候选 | 本轮基础 |
|---|---|
| ABB10 CRYPTO ROM | 复用完整实施规范；增加固定维度变换/完整核基的代数对照 |
| CHKP ROM | 复用原文、规格和队友任务书；增加真实ExtBasis公共整数代数检查 |
| LATTE | 原稿、算法/实现/精度入口、匿名性待核条件；共享环算术/NTRU方程教学对照 |
| GKR2025 | 用户34页完整稿；定位§3编译器/Theorem3.1、底层依赖和匿名LWE扩展的lockable obfuscation |
| Zhang2020 | 保留原稿与类型/参数疑点；共享环算术基础；语义澄清后才实现 |
| ABB标准模型选择性HIBE | 独立模型对照；不能将§7自适应IBE结果套给§8 HIBE |
| CHKP§5.4标准模型变体 | 独立条件/哈希/维度入口，不能与§5.3 ROM参数混用 |

| IBS候选 | 本轮基础 |
|---|---|
| Luo矩阵 | 复用真实后端；重新跑一次小参数Setup/Extract/Sign/Verify和公开反向检查 |
| Luo模格 | 复用真实后端、参数/Hint账本及规范格式；重新跑一次实际参数单体和无损差分 |
| SRGG2025 | 用户12页完整稿，恢复完整公式审查入口；旧强结论/模数映射/尺寸问题继续保留 |
| Yu2026 | 用户26页全文；定位§3.1服务模型、§3.3 Figure5/Theorem3及双PRF/公开私有同态求值依赖 |
| Sageloli矩阵SIS | 新取得完整稿；Figure5/6、Table2、转换及每签名发钥游戏的对应 |
| Sageloli Ring-SIS | Figure7/8、Table4、复合模数环和AppendixE单位/参数计数核验 |
| Foo–Li | 复用固定种子/MP12/生命周期/条件归约；当前研究生命周期不当正式IBSBackend |
| Wang+PW | 复用原论文和固定服务审查；现有非自适应教学后端不当完整自适应方案 |
| 认证转换+ML-DSA | 保留通用转换、普通签名规格和完整认证载荷任务，作为工程比较储备 |
| 认证转换+Falcon | 保留转换、NTRU采样/精度/编码入口，作为工程比较储备 |

**全部候选已有统一基础卡，尚未全部实现/实跑四算法。** 深度按卡明确记录：原稿归档、公共代数、参数计数、单体算法、完整组合、合法参数是不同进度。复杂编译器或存在未澄清语义的方案先交依赖图/对象/条件；不会生成一套只抛NotImplementedError的“后端”，也不把公共方程成立称密码方案实现。

## 2. 可直接复用的实验

`experiments/research/candidate_preflight.py` 在指定 WSL Sage 环境真实执行，见 [preflight.json](preflight.json)：

- CHKP 的ExtBasis代数：$q=17$、$n=2$、根$m=4$；两次扩展得到4/8/12列，完整整数基满秩、模核关系和行列式均正确，行列式绝对值始终为289。
- ABB 固定维度对照：同一公开小矩阵和模可逆整数变换；直接乘原基得到子格，指数分别2和6；公开长核基补全保持维度4和行列式289。乘法不等于完整BasisDel，此对照可以防止队友实施时遗漏基补全。
- 环基础：$N=8$，对素数$q=17$和复合$q=81$，整数负循环卷积与Sage商环一致；公共平凡NTRU整数恒等式成立。这不是NTRU密钥生成，也没有环高斯采样。
- 两套已有Luo单体：Alice5 B、消息10 B，各一次真实四算法、规范加载、错身份/改消息拒绝；矩阵默认小参数签名259 B，模格参考29455 B、压缩16063 B。矩阵947 B的前轮样例使用另一配置，不能混为同一结果。实际全部参数记录于JSON。

公共核基和ExtBasis对象没有短性、Gaussian或秘密性保证，包含可见父基，**不可签发给任何用户**。它们只提供基础代数和独立体积验收。没有新增HIBE、安全参数或完整IBME；旧教学负面对照未被关闭。

## 3. 新论文得到的具体信息

### Sageloli：速读结论与单位账本

核心是把每条消息的承诺改为非齐次syndrome，让签名直接调用已有身份陷门的SampleD，减少第二次消息委派。详细算法在矩阵Figure5和环Figure7；§5给出自适应转换，§6/7给出原语，§8给参数和比较。它适合Ring-SIS扩展和与Wang/PW比较，但实际尺寸与采样资源不能仅按标题“更短更快”理解。

HAL v1的Table7将ParamI描述为129bit估计、签名20Mo、身份私钥699Mo；这不是本项目的安全位数或实测。AppendixE（PDF71–72页）以“系数数量乘log2范围”计算bit，再除以10^6打印为Mo，未除8。本轮按原附录转录计数，在 [sageloli-units.json](sageloli-units.json)中保留原标签数值、bit、字节换算和定宽计数，未替作者修改原文件。

| ParamI计数项 | 附录打印的数值（标签Mo） | 统一bit→byte的估计 |
|---|---:|---:|
| 签名 | 19.88 | 2484914 B |
| 主公钥 | 27.85 | 3481339 B |
| 身份私钥 | 698.98 | 87372131 B |

这些是附录信息量计数的换算，**不是已实现的wire长度**。主公钥每系数固定104bit的精确计数为3514368 B，还未包含格式头；浮点宽度/概率条件尚未认证。$q=3^{65}$或$3^{153}$是复合模数且超过现有uint64模块参数范围，不能套Luo素数NTT或截断。读者建议先§5/§7的Figure7/8与Table4，再§8与AppendixE，最后定位所引用条件；无需重写整篇QROM证明。

Figure1（PDF11页）的OSign每次调用KeyExt，没有固定用户密钥缓存。算法可以保存身份盐r，但从这个安全实验到我们的固定密钥服务仍需核对，不能仅据“自适应”标签批准。值得继续做有限环实例和成本对照；目前不预定为最终代表，也未声称论文被攻破。

### 用户提供的三篇

GKR完整稿确认一般自适应编译器的PKE、OTSE、garbling、可委派PRF等依赖；匿名LWE扩展另见AppendixB的lockable obfuscation。基础准备先给出这些依赖与电路/状态开销，不自行改造为“简单LWE矩阵HIBE”。

Yu稿的§3.3明确给出独立IBS Figure5/Theorem3，依赖SIS与双PRF；公开/私有同态求值、gadget、委派及Gaussian条件仍需有限实例。它的独立IBS可以调查接Wang；论文另一套IBE+IBS通用构造不替换已固定主线。只给IBS标准模型标签，也不会自动使与ROM HIBE的完整组合成为标准模型。

SRGG稿已恢复完整数学公式；旧核验的Theorem2底层sEUF-CMA前提及q/Q/2Q映射、表格差异没有因为取得PDF而自动消失。接手先做逐式对应，优先引用已有结论；遇到具体缺口明确列出，不默认重做基础证明。

## 4. 顺序与选择规则

1. **全候选基础准备**：本轮完成来源、统一卡和可复用最小实验；后续按卡补有限公共对象/采样/参数单元，所有方案都有进度，不能无限补文档。
2. **首套完整实现**：优先以已有Luo和队友CHKP建立完整平台，完成五算法、固定发钥/恢复、全部匹配与攻击验收；它是第一套可测基线，不是预定冠军。暂不继续独立压缩或无关跑分。
3. **逐套替换与重要比较**：分别替换HIBE或IBS，隔离组件差异；继续LATTE、SRGG、Yu、Sageloli、Foo–Li/PW等小单体和适配。材料/条件不满足的路线也记录具体失败、模型差异及资源成本，不从比较表删除。
4. **选三个场景代表**：按相同目标与完整组合数据选择，随后做组合优化及消融，最后交付竞赛系统。

| 场景 | 主要选择指标 | 必须共同记录 |
|---|---|---|
| 带宽/终端资源受限 | 完整密文、公钥/用户钥、峰值内存和解密时间 | 主机构/委派成本、真实参数、失败率、采样/精度条件 |
| 在线高频消息 | 完整Encrypt/Decrypt热态延迟、吞吐、在线/离线边界 | 冷态及预处理、离线库存/内存、新随机性、失败重试 |
| 多用户和长期固定密钥服务 | 发钥/委派、持久化恢复、缓存增长和重复消息能力 | 两层固定深度、身份数量、参数/上下文隔离、腐化/伪造验收 |

不要求三套在所有指标都最优；需要有互补优势，依赖和算法统计真实。先采用相同四种身份匹配、字节完整性和固定密钥服务目标，身份典型5/3 B与最坏64 B，公共应用长度0/32/1024/3924 B；特定方案输入空间较小先明示适配及共同可比子集，不偷偷截断消息。正式参数、机器、计时边界和认证包装须一致。原语QROM/标准模型性质另列，不自动升级整个组合。

$A+B<C$的目标保留在完整实现之后：同目标的未优化基线、单项及全部消融，包含准备/采样/序列化等约定成本。公共计数/库复用不是速度或密码原创证据。

## 5. 队友如何接手

打开逐项卡，选择自己认领的候选ID，在其 `experiments/research/candidates/<id>/` 建数学/原语参考和对应测试；本轮只给文件范围建议，没有创建线程、派发新AI或发送消息。现有CHKP负责人继续原T1–T4；其它候选先完成卡中的前三项。更换负责模块需遵守同一时刻一人一文件。

每次交接包含：原文版本与算法/定理编号、实际对象/维度、合法条件、最小正/负用例、序列化资源、固定身份状态与恢复、所有参数、未实现项；Gaussian不能用均匀数代替。单体通过后由主AI冻结独立参数/wire并接入已有HIBEBackend/IBSBackend，主AI负责完整Wang/认证/CLI及整体攻击验收，不读取后端内部私钥字段。

## 6. 验证与文件

Windows Python3.14.6/pytest9.1.1：`python -B -m pytest -p no:cacheprovider -q tests/test_candidate_foundations.py`，24 passed。指定 WSL Sage10.9/Python3.13.14：`~/miniconda3/envs/sage/bin/python -B -m pytest -p no:cacheprovider -q tests/test_candidate_foundations.py tests/test_candidate_preflight.py`，37 passed。无XFAIL，Windows未运行Sage代数模块；不是17套原语契约通过。硬件为Intel Core Ultra9 275HX，实验环境字段记录于结果；没有密码性能测量。

复现入口：

```text
python -B experiments/research/candidate_catalog.py --output test-results/candidate-catalog.json --cards docs/research/2026-10-10-foundations/候选基础卡与队友接手任务.md
python -B experiments/research/sageloli_parameter_units.py --output test-results/sageloli-units.json
wsl -- bash -lc "cd /mnt/d/zcode_projects/ibme && PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -B experiments/research/candidate_preflight.py --output test-results/candidate-preflight.json"
```

原PDF以原样/指纹归档，无TeX。抓取失败与用户随后补齐分别保留历史记录；重跑fetch脚本不会覆盖现有缓存。新签名/私钥状态只在内存中，没有导出私钥、随机带或种子。

首次公共环探针误调用了只接受稀疏挑战的函数，实跑报TypeError；已改为一般整数卷积并复跑成功。用户稿标题校验遇到PDF连字/断空格，统一Unicode和空白后验证通过。当前测试与所有最终复现命令无失败；没有将这些工具问题归因于论文或密码算法。

本轮修改范围：`experiments/research/candidate_catalog.py`、`candidate_preflight.py`、`sageloli_parameter_units.py`、`fetch_candidate_sources.py`；两项对应测试；本目录catalog、生成卡、公开结果及报告；Sageloli PDF、获取记录和papers索引；AGENTS、README、项目记录及主AI工作单更新流程。此前三篇用户PDF及其指纹另属683b0e3，不混进本轮算法基础提交。

WIP：绝大部分候选还没有完整原语/协议后端；正式参数及论文/服务条件未全部核对，合格完整组合0，最终三套未选。默认education的两个认证反例仍存在，基础卡/代数/计数不能修复它们。全部 `security_claim: none`、`backend_admitted: false`。
