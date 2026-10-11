# 首套集中闭环：主密钥—父级委派—固定叶钥的可恢复发钥树

2026-10-11。基点 `a247b0c`；该提交的两项远端 CI 已确认 success。本轮继续第一套 CHKP/Luo/Wang 的集中闭环，新增主/父级私有对象，不扩展备用候选。完整七入口、生产采样/实际参数和组合仍 WIP。

## 实现及原文对应

`experiments/research/first_suite/delegation_state.py` 对应 CHKP §5.2–5.3：`DelegationScope` 冻结根公开上下文、根 GS 上界、父/叶 Gaussian 宽度、source profile、误差和容量；`MasterTreeState` 保存完整根基及固定父级对象；`ReceiverState` 保存可委派完整父基和上一轮 256 位 `FixedSeedState`。真实公开矩阵仍由有序 H/G 重算。它们不是 GenBasis/RandBasis/GPV 算法或完整 HIBE 后端。

- 同一接收者从同一个主对象签发一次父基，同一发送者从同一个父对象生成一次256原像；重取及恢复不调用生成器。
- 根、父私钥在原语内部验证完整核格：`A*S=0 mod q`、完整行列式 `q^n`、有序身份及声明 GS 上界。恢复叶向量继续核对真实 H/G 方程、范数及固定位置。
- 主树统一锁串行化父/叶修改和嵌套快照，避免两种锁序相互等待；运行中的快照保留FAILED。主、父失败和叶失败都跨序列化阻止自动重抽。
- 主树和单独父钥均以版本/类型/长度前缀编码、规范有符号整数和排序地址序列化；拒绝未知版本、截断/追加/重复/身份或scope不符及坏基。主树恢复重新接上共享锁和预算控制，不序列化锁、回调或RNG。
- 整个主树及单独父钥均≤16MiB；发父钥前预留完整方阵，生成新叶之前同时预留父钥和整树最坏增长。资源拒绝不保留地址、不调用私有生成器；容量固定且不淘汰。

生成器是受信任的格采样适配；关系和GS校验不证明其分布、RandBasis来源或GenBasis近均匀。测试中的公开完整核格/公开pivot向量只验证状态；另有真实有限RandBasis/GPV和qFALL/原生GPV接线。

## 实际遇到并解决的问题

有限参考的4维RandBasis输出可以有极小GS长度，随后SampleD拒绝标量宽度超限。实际有限Gaussian控制预先固定执行已有 `reduce_basis`，再生成叶钥；没有修改硬上限，也没有在随机失败后重抽或切换profile。该控制的根仍是公开教学基，不宣称陷门安全。

较大输入的父/叶生成及快照已完成，但第一次独立恢复因60秒超时终止。排查发现完整基被重复做精确有理GS。现在解析仅校验完整核格，构造阶段校验GS一次，并先采用严格充分证书 `max_i ||b_i||² <= B ⇒ max_i ||b_i*||² <= B`。证书不成立时仍执行原来的精确GS；大平行分量而GS合法的测试仍接受，实际超GS的坏基仍拒绝，未改变原条件的接受集合。

复用已经保存的快照后，独立恢复用时 **0.499 s**（不含解释器/Sage导入），没有重启发钥或重新采样。未来探针在启动子进程前保存非秘密生成回执，恢复/观测失败不再丢失已经完成的阶段证据。

## 实跑证据

| 输入 | 结果范围 | 主树/父钥wire | 原始KEM |
|---|---|---|---|
| n=1,q=17，13/26/39维 | 当前版本完整运行；父级生成1次/26个native向量，叶级生成1次/256原像；独立主/父恢复及两类墓碑通过 | 77592 / 75557 B | 392 B，随机32 B种子121位错误，保留负面对照 |
| n=1,q=1073741827，79/158/237维 | 原运行生成后在恢复超时；使用同一现存主树/父钥/密文完成修复后的独立恢复，256固定向量和种子散列一致，两类墓碑均阻止生成 | 646884 / 608082 B | 2069 B；恢复种子散列匹配，新增父/叶生成均0 |

较大行未保存原native父抽样计数、完整流水线耗时，机器结果明确为null；不从维度或上轮输入猜数，也不把恢复0.499s写成原生成耗时。该回执缺口不影响已有快照的数学/身份/固定向量恢复验收，但限制本次生成统计。Private文件全部保留在被忽略的 `test-results/`，报告只保存参数、计数与散列。

两行来自上一轮同一公开固定测试输入/上下文，内部P/C身份均86B，原身份Bob/Alice为3/5B；父/叶s²分别为62320/252769920和2441960/63276067520，alpha=4/q，q*alpha=4，真实取整噪声tail64/mass96/precision160。每次32B种子封装的独立噪声调用分别295/493。Sage10.9/Python3.13.14，Intel Core Ultra9 275HX。各行只一个预定测试流，不是参数安全/批量可靠性证据。

Sage相关回归 **129 passed**，覆盖新主树、真实有限RandBasis/GPV、实际qFALL小q生命周期、既有H/G/256位/噪声及基/规约/随机化测试；不是全仓测试总数。源码、库、环境、完整文件/命令、初始失败和未完成项见 `audit.json`。

```bash
PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -m pytest -p no:cacheprovider -q --tb=short \
  tests/test_first_suite_delegation.py tests/test_first_suite_identity_state.py \
  tests/test_first_suite_seed_sage.py tests/test_chkp_basis.py \
  tests/test_chkp_basis_reduce.py tests/test_chkp_randbasis.py \
  --junitxml=test-results/first-suite-tree-regression-sage.xml

# 需要上轮qFALL本地binary；只用于公开教学输入。
PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -m experiments.research.first_suite.tree_probe \
  --only-q 1073741827 --private-directory test-results/first-suite-tree-qbig-fresh/private \
  --output test-results/first-suite-tree-qbig-fresh/result.json

# 已有生成产物时只恢复；不要因恢复超时自动重启发钥。
PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -m experiments.research.first_suite.tree_probe \
  --restore-only test-results/first-suite-tree-qbig/private/public-restore-manifest.json
```

## 边界与下一项

私有快照不认证存储、不抗回滚。主树与父钥单独导出后可能形成独立副本，本组件不跨进程/机器同步副本：唯一发钥树和唯一接收者状态仍是条件。接CLI时必须沿用已有本地锁/pending和“已有接收者文件经验证复用”，不能用旧主快照覆盖较新的接收者文件或在同一地址发新对象。

主/父/叶数学对象的连续生命周期现在有实际证据；源采样的CSPRNG/有限误差、同组实际安全参数、完整公开/秘密HIBE对象及七入口/字节契约、Luo引用条件和完整Wang/HYBRID/BYTEAUTH攻击验收尚未闭合。下一项转向真实后端接口与生产采样/选参准入，不继续重复同一教学输入的扩样或独立优化。所有声明仍为 `security_claim:none,backend_admitted:false,parameters_are_formal:false`，经典ROM引用不升级QROM，测试不是安全证明。旧education两个认证反例未由本轮消除，整体目标继续保持。
