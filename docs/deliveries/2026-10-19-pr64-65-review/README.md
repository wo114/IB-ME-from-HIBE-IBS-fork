# PR64／65 合入审查

2026-10-19，以main `a9d9615`为集成基线。PR62、63已由此前操作合并，本轮不重复记为自己的合并。本次审查未启动子智能体、未改旧作品报告或PPT。

## PR65：修复后接收

原head `8e4068f825d445f3283d249ca8a8fa22f6614716`，修复及合入最新主线的提交为 `8e87066b094796b9380d261da32291e5d3bc92f5`。

- **root-Hermite公式错误**：原指数1/(b−1)缺少1/2，会把因子平方并高估攻击成本。对照[lattice-estimator固定源码](https://github.com/malb/lattice-estimator/blob/e4333d9bf9ef42fd8a29651b0c559fba7ce0d834/estimator/reduction.py#L72)修正；53、100、500三个块尺寸的参考值先在旧代码上全部失败，再修复通过。
- **搜索上限被当成有限精确成本**：原实现找不到b≤1200的攻击时直接返回上限成本。现将其标为未括住的搜索结果，序列化为空并排除目标选择；负例先失败再通过。本次240个门外案例均在范围内括住，没有用此状态充数。
- **有限网格被推广为全部后端否定**：实际只取每位长最大素数、n≤4、九档宽度；浮点预筛还有四比特余量且未采用完整C2宽度界，不能作严格拒绝证书。JSON新增范围和非严格预筛标志，文档收窄结论。一个n=5的后端可接受形状证明覆盖并不完整，但不把它当作安全候选或新实跑结果。

重算240个门外案例，参数、解析检查、范数和LLL排除结果保持原值；修正成本后为130个解析失败、64个LLL界排除、44个经典估计不足128、2个仅经典估计达到128。原n2048的147.17/133.56降为51.39/46.64；最小已测经典候选移到n4096，估计129.94/117.93、公钥比特打包约63.0 GiB。没有双128候选，没有生成目标密钥或签名。

修改文件为`experiments/research/foo_li_parameter_improvement.py`、对应测试、[完整JSON](../../research/2026-10-19-parameters/fooli-improvement-search.json)、[参数卡](../../research/2026-10-19-parameters/FooLi参数改进搜索与128bit目标卡.md)和[当前进度](../../PROJECT_STATUS.md)。同时按已接收PR63更新默认接入7种IBS及Sageloli v3 PARAM-I完整配对事实，未恢复PR57。

## PR64：保留作者草稿

固定head `d20642d78fef7ac8a45d311569cc54cdc897cb3d`。审查了322行跨IBS驱动、三份来源快照、绑定校验器和声明范围。四种组合共用一个真实C2根与两个一级钥，每个身份场景计划在新进程进行真实委派；不把并发计时称为独立根基准。新建目录、失败保留、原始状态不改、明确研究标志均按代码核对。

本轮只在该head的独立Git导出源树做四Suite静态预检及13项收据/工作目录回归，没有启动四种C2目标生命周期。最初预检因本机缺ML-DSA原生引擎拒绝；从固定源树在独立缓存新建ML-DSA/Falcon与Sageloli原生核后，四项预检通过。没有回退算法或把缺依赖当作密码拒绝结果。

当前49项来源绑定与原历史44项绑定均通过；三份快照逐字节对应声明的`aa8dd3e` Git对象。另在临时隔离fixture验证：未声明Lai运行源码修改、快照损坏和越界快照路径三组负例全部拒绝。[控制流程结果](pr64-binding-controls.json)中的target_c2_rerun=true指核对PR62原有收据，**本轮fresh_C2_lifecycle_runs=0**。历史267项JUnit是作者原批次，不是本轮新跑267项。

PR64仍为作者草稿，说明真实运行结果将另行归档。本轮保持该状态，未抢先标ready或合并，也未改动运行中的交付分支。

## 本轮验证

本机i9-14900HX，规定WSL Sage10.7/Python3.12.13、OMP4/OpenBLAS1；来源fixture用Windows Python3.14.0a5。测试耗时不作为密码方案速度。

| 实际执行 | 结果 |
|---|---|
| 原PR65两个参数分析测试文件 | 37 passed，48.46秒 |
| 新增覆盖范围负例 | 原版1 failed；补范围标志后通过 |
| 三个root-Hermite参考及截断负例 | 原版4 failed；修复后通过 |
| 修复后两个参数分析文件 | [42 passed](fooli-final.xml)，49.10秒，0 failed/error/skip |
| PR64 `tests/test_lai_target_receipt.py` | [13 passed](pr64-receipt.xml)，3.68秒；含fake CLI路径控制流，不是C2实跑 |
| PR64四配置 | [4项静态预检](pr64-plan.json)通过，execution=not_executed |
| PR64来源绑定隔离fixture | 1正例、3负例符合预期 |

42与13合计55个不同测试身份；不重复累计原37或作者267项。公开JUnit只删除hostname，保留结果与时间。固定源码、文件摘要与各次测试版本见[review.json](review.json)，不会把新证据挂在旧算法快照上。

```text
# 激活规定Sage环境，PYTHONPATH=src:.，PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
python -m pytest -q tests/test_foo_li_parameter_improvement.py tests/test_foo_li_parameter_screen.py
python -m experiments.research.foo_li_parameter_improvement --output <新的分析结果路径>
# PR64的13项测试应在上述固定head的独立源树中执行
python -m pytest -q tests/test_lai_target_receipt.py
# 标准库离线复核本记录
python docs/deliveries/2026-10-19-pr64-65-review/verify.py
```

原始必跑CI在审查开始时均无失败；修复后应以PR65新head检查为准，不沿用旧head全绿。最终合并状态见[PR65](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/65)，草稿状态见[PR64](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/64)。安全性和HIBE匿名性沿用项目论文/工作假设，实际参数声明仍none/false/false；Foo–Li目标估计不是安全等级准入，实际大参数后端、采样及完整系统实验仍未完成。
