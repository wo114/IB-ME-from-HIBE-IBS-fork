# PR69／72／73 接收与 PR71／74 证据衔接

日期：2026-10-20。审查从远端 `7caaff4` 开始，随后接收 main `b9d219f`。本次沿用用户明确授权审查、修复和合并；不启动三条暂缓路线，不重做安全证明，也不把本机内存门槛写成算法普遍不可行。

## 版本与处理

| PR | 固定审查输入与处理 | 证据范围 |
|---|---|---|
| [69](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/69) | 原头 `3c039f9`；修订 `e6423b0`；46成功、2个预期手动项跳过后合并为 `aced883` | A09：3个独立CSPRNG根、每根2×2身份配对、0／1／32／1024 B消息、60项结果；固定运行源码 `85a93e2` |
| [72](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/72) | 原头 `fef232e`；修订 `3c3cda3`；46成功、2个预期手动项跳过后合并为 `b9d219f` | A/B同机各3根、9对热运行和9次恢复解密；三组64条CLI与3个内层负例进程；固定源码 `eeb3108` |
| [73](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/73) | 原头 `de867bd`，后续版式 `b43f2d0`、官方模板 `b986db7`、同步头 `6831e30`全部保留；修订提交见下表。远端合并以前须检查修订后的精确头 | 显式provider登记、已完成配置安全标记、旧状态兼容、当前三代表及官方模板LaTeX／PDF |
| [71](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/71)／[74](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/74) | 本轮开始前已合并；重新只读核验原安装证据 | B精确128 KiB、15条CLI；C精确8 MiB、12条CLI和有效外层下的内层负例，与PR72分批记账 |

| 本地接收提交 | 内容 |
|---|---|
| `e6423b0` — `fix(review): receive PR69 and keep evidence verification portable` | 保留原收据；POSIX资源统计延后至真实worker导入，使Windows只读校验可运行 |
| `3c3cda3` — `fix(review): receive PR72 evidence without double counting` | 保留压缩后的当前进度结构，区分独立批次、重复基准与安装功能观察 |
| `e36173a` — `fix(review): apply secure defaults and repair PR73 integration` | 执行用户最新安全前提，修复原语、CLI、Web和收据兼容；修复SRGG有理数存储上限 |
| `76d4121` — `docs(report): receive PR73 layout with reviewed evidence` | 接收作者后续版式，保留新补测表与最新安全前提 |
| `42f5c93` — `docs(report): receive official template and preserve reviewed defaults` | 接收官方模板和匿名相对路径，保留当前安全配置及严格B配置绑定，重编最终31页PDF |

完整修改文件、源码字节绑定与实际测试摘要见[review.json](review.json)。原始PR提交和收据均保留，接收使用合并提交，不覆盖作者历史。

## 发现与修复

1. PR69只读校验曾在Windows顶层导入POSIX `resource`。资源测量改在真实worker内导入；原60项收据和源码绑定不变。读取旧收据时只规范化三个安全字段，仍比较完整算法、参数、版本、格式与预算。
2. 用户本轮明确要求“就认为是安全的，不是本项目准入”“默认已经做好的都是安全的”。AGENTS及公共登记已改为已完成算法及冻结采用的论文／目标配置默认安全，使用 `secure/true/true`。已知公开攻击调试档、mock、只有投影和未完成实现仍分别记录，不借本次政策改变旧实验值。
3. PR73新配置与旧收据不兼容：若干运行探针写死none或旧Suite摘要。改为从实际Suite复制安全字段，旧快照仍可读取；新三代表保存当前摘要和原evidence摘要。当前B、C探针严格绑定各自完整冻结配置，错预算必须在发钥前拒绝。
4. PR73原push曾在真实SRGG PARAM-I生命周期报 `anisotropic center exceeds scalar rational reserve`，coverage随之失败。论文后端已经允许8192项级数，原标量有理数上限却只有8192位。新增仅供论文后端使用的32768位精确有理数储备；原调试／优化后端仍保留8192位。未改变n、q、宽度、级数项数、精度、tail/mass、尝试帽、熵或有限高斯分布，也没有新增换根重试。定向测试验证大分母可接受、旧配置仍拒绝、原可接受输入的有限概率质量逐项相等，并实际运行reference和compact生命周期。
5. 当前报告已增补PR69和PR72、删除B／C已完成安装和内层负例待办，保留C最大消息及有限多根重复。官方模板的两份DOCX、四边20 mm页边距与内嵌标志已独立按字节及XML核验。报告改用支撑材料相对路径，保留31页、12张表、6幅正文图、19个证据入口和15条文献。

用户误删的 `docs/research/2026-10-19-lai-c2-combinations/README.md` 末尾句号和空行已精确恢复到原HEAD；恢复后该文件没有差异，不额外制作空提交。D盘共享工作目录未切分支或改写他人文件。

## 实际验证

测试使用规定的WSL `~/miniconda3/envs/sage`，并设置 `PYTHONPATH=src:.`、`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`、`OMP_NUM_THREADS=1`、`OPENBLAS_NUM_THREADS=1`。只读证据复核另用Windows Python；两类用途分开。各测试组有重叠，不合计成新的独立样本数。

| 命令（`python -m pytest -q`后的选择） | 结果 |
|---|---|
| `tests/test_random_batch_acceptance.py tests/test_cli_selection.py tests/test_byteauth.py` | 91通过；导入修复后batch定向15通过 |
| `tests/test_report_experiment_probe.py tests/test_cli_selection.py tests/test_ci_catalog.py tests/test_report_fooli_bindings.py` | 93通过 |
| `tests/test_srgg_paper_samplef.py tests/test_srgg_wide_scalar.py tests/test_srgg_paper_assembly.py` | 85通过，0跳过，含真实PARAM-I生命周期 |
| 公共接口、CLI、状态、Web、探针和配置兼容，完整选择见review.json | 216通过，0跳过 |
| `tests/test_cert_ml_dsa_contract.py tests/test_cert_falcon_contract.py tests/test_lai_hibe.py tests/test_latte_metadata.py tests/test_srgg_paper_registration.py tests/sageloli_native/test_ring_assembly.py` | 102通过，0跳过 |
| 最新精确B约束后的 `tests/test_srgg_paper_cli_probe.py tests/test_report_experiment_probe.py tests/test_random_batch_acceptance.py` | 35通过，0跳过 |

最初安全字段集成的3项探针失败已保留摘要，随后216项和最新35项通过。一次误选不存在的测试文件没有执行测试，不计作通过。最终JUnit删除机器hostname属性后放在[evidence](evidence/)中；测试断言及计数未改。

只读复核命令和结果：

```text
python docs/research/2026-10-19-primary-random-batch/verify.py --self-test
python docs/deliveries/2026-10-19-report-experiment-supplement/verify.py
python docs/deliveries/2026-10-19-report-experiment-supplement/verify.py --negative-controls
python docs/research/2026-10-20-report-b-installed/verify.py --self-test
python docs/research/2026-10-20-report-c-installed/verify.py --self-test
python docs/deliveries/2026-10-19-report-three-selection/verify.py --self-test
python docs/deliveries/2026-10-19-report-three-selection/verify.py --assembly --self-test
python docs/reports/2026-10-19-research-draft/check_latex_report.py --require-pdf
git diff --check
```

分别通过A09的60结果／405来源绑定／5负例、PR72的5219一致性项／3个重新哈希仍拒绝的语义负例、B的5个篡改控制、C的6个篡改控制、选型63项／5负例及三组真实装配预检。报告160项通过。它们不表示重新生成了原实验的密钥或密文。

当前[PDF核验](pdf-qa.json)为31页A4、20种字体全部嵌入、无Unicode替换字符；八张联系页覆盖全部31页，另单独检查同机A/B表所在第30页。编译仅出现本机fontconfig默认配置缺失提示，无LaTeX溢出、缺字或未定义引用警告。`--submission-ready`实际仅因尚未填写作品编号而拒绝（1/161项），未把工作稿误标为上传件。

## 参数、安全前提与剩余边界

新配置按用户决定默认安全，三代表具体参数不变：A为LATTE seed32＋BNN/ML-DSA-44、64 KiB；B为LATTE seed32＋SRGG PARAM-I compact、128 KiB；C为Lai C2 n2048＋Sageloli RSIS v3 PARAM-I、8 MiB。外部身份上限64 B；主要重复基准消息32 B；安装补测长度及次数由各批次原始记录决定。论文安全目标、HIBE匿名性及ROM／QROM模型按选定原文和用户前提分别说明。不是教学档；不新增整体NIST等级或标准模型结论，功能测试不替代安全证明。

PR72原 `/tmp` 私有状态在WSL重启后丢失，原备份为0 B；公开收据和wheel仍在，但不能移交原状态。报告与当前进度已保留这个限制。C每次现有CLI解密实际重新委派并消耗新熵；不写成零熵恢复。

尚未完成：C的3924 B最大消息诚实往返、有限多根重复、同一最终发布版本干净复现、完整来源许可清单、系统作品编号及最终匿名／提交材料复核。Web仍只展示既有LATTE三预设，服务重启恢复使用CLI。新PR75仍是准备复用与完整消融草稿，本交付不把它的在途实验提前列为已完成或已合并。

## SRGG固定源码证据的后续修复

审定头`3af5d5a`的远端SRGG作业随后报告2085通过、18失败及2个错误：新增算术储备改变了两份历史研究源码的整文件摘要和标量选项类，触发旧证书的严格版本绑定。提交`bdffe26`将运行适配移到独立`paper_runtime.py`，公共后端引用该适配；`paper_backend.py`和`paper_samplef.py`已逐字节恢复到原`7caaff4`，旧清单、收据、选项类和输入域保持原值。既有证书继续描述原研究实现，不将其边界扩写为新运行适配的验证结果。

失败模块及真实公共生命周期联合回归142项通过、0跳过；新运行路由、精确存储边界、登记与CI目录68项通过、0跳过。两个组有重叠，不相加。新路由测试验证公开运行接受长精确中心、历史后端仍拒绝，除有理数存储上限外的所有标量选项相同。新源码绑定和JUnit见review.json的runtime_source_followup。三份Suite摘要、原始实验字节和已核验的报告PDF均未改变。

## 已知参数反例的清单修正

后续审查发现原PR73还把Luo矩阵`research`列为完成的安全配置，但实际参数n=4、m=8、k=32、q=2147483647、η=1、κ=8、γ1=4096、γ2=131072与2026-10-09 M2 functional完全一致。该原记录已有等效主秘密恢复及有效伪造，属于用户前提中明确排除的已知反例。现已保留其研究执行接口并恢复`none/false/false`；Luo模格、报告三代表及其Suite摘要不受影响。本次没有执行新的攻击实验。

AGENTS同时明确：已完成方案默认安全，不另设“本项目安全准入”阶段；已知不安全的小参数仍照实排除。代码修正`55b2c12`与目录计数修正`338767a`已完成；最初回归中的旧安全目录集合／数量断言已更新，最终政策和目录33项通过、0跳过。证据、实际参数和JUnit见review.json的known_parameter_exception_followup。
