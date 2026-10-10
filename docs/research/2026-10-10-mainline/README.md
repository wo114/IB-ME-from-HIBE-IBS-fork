# 首套接入第一轮：固定密钥状态与参数快照修复

日期：2026-10-10；基点 `292b958`。已核对远端，无新增提交或开放PR，仍未收到CHKP实现。本轮按[关键路径](../../workplans/2026-10-10/首套系统关键路径与优先级.md)推进首套已有Luo IBS/协议状态，不继续SRGG/Yu采样或独立优化。

**已修复真实的并发发钥与参数快照缺口。** 修改前新增回归实际为10 failed/1 passed：同身份并发产生不同密钥、不同身份并发丢缓存，以及8种底层HIBE参数漂移被固定profile接受。它们违反本项目状态/配置要求；不把这些反例描述成新的IBS伪造攻击。最终结果和源指纹见 [验收记录](admission.json)。

## 1. 修复了什么

1. **CLI状态读改写。** Setup、发送/接收者发钥从读取主状态前至缓存/密钥发布后持有同一本地OS锁，避免两个独立进程都从旧快照发钥后覆盖对方。同身份两次得到相同密钥，不同身份均保留。接收者发钥也写回主状态，为后续有缓存的HIBE保留接入条件。
2. **库内同一主状态。** LuoModuleMasterSecret以重入锁保护key_extract的缓存检查—生成—插入及序列化快照；同一主状态被两个后端线程使用也保持一份身份密钥。锁不进入wire/RNG状态，from_bytes重建新锁。
3. **完整文件发布。** 主缓存先提交，密钥文件随后通过同目录临时文件、flush/fsync及原子替换发布。主状态提交失败时不发布新密钥；密钥文件发布失败时可从已提交缓存重试同一密钥，临时文件清理。读者不再看到被截断一半的密钥文件。
4. **防误覆盖。** 已有研究状态不能通过改选education/mock或再次Setup绕过保护。参数/格式预检先于所有状态文件/目录写入。回归曾发现本轮初版锁包装提前创建目录，已修复该兼容性问题。
5. **固定HIBE快照。** profile检查公钥及各级秘密对象中的公开n/m_bar/q、身份/载荷上限及s0/s_enc/s_pre；与冻结配置不符即拒绝。只读公开参数字段，不读取陷门或私有矩阵。测试包含完整合法的另一套q配置，排除仅靠底层解析错误拒绝的假验收。

状态锁文件`.ibme-issue.lock`只含一个零字节，永久保留；不存身份、种子或私钥。Windows用msvcrt字节锁、POSIX用flock，默认最多等待30秒；忙或文件系统错误明确失败，不回退无锁执行。强制终止进程后OS释放锁，不靠删除锁文件恢复。

这个锁的保证限定于同一OS的本地文件系统。未验证Windows/WSL混合进程共同写同一目录、网络盘或跨主机；不宣称硬断电下的多文件事务或私钥仓库加密。可信本地状态目录及通过本库接口进行缓存访问仍是运行条件。

## 2. 论文—代码—组合条件对应

来源：[Luo等ICICS2024固定稿](../../../papers/2024_ibs_without_trapdoors_luo.pdf)，20页，SHA-256 `12c70ae7635c0b88c132bca14990480a8e0cdec2e786a6dcf39256e5bb0dd455`。实际复核PDF6/9/13–16页，并渲染PDF9/14页确认缓存语句、签验算法与不等号。本轮不重做基础安全证明。

| 所需条件/原文位置 | 实现及本轮结论 |
|---|---|
| §2.2 Definition3，PDF6：自适应EUF-ID-CMA | 身份/消息可适应选择，公开Verify不依赖私钥；与项目普通IBS目标对应。引用仍使用经典ROM范围，不能授予QROM |
| §3.2 Theorem1及Algorithms5/6，PDF8–9 | Theorem1是矩阵方案的定理；PDF9重复Extract Oracle返回旧值，Algorithm6调用该oracle。继续采用共享有状态oracle解释，本轮修复其真实并发/持久化实现；不宣称该解释已获作者确认或完整模拟前提已闭合 |
| §4 Algorithms13/14，PDF13 | A真实均匀、s1/s2为有界均匀系数、t=As1+s2；Extract掩码/H1/z1/z2及≤边界对应。均匀掩码是原文要求，没有冒充高斯。参数不变 |
| Algorithms15/16，PDF14 | Sign严格范数、r0/w0c拒绝、Hint和公开挑战恢复式对应。第9行zid按正文/Verify解释为z；本轮没有改算法、随机性或完整H1/H2输入 |
| §4.4，PDF15–16 | 模格部分明确是security reduction sketch，依赖MLWE/MSIS；不能把矩阵Theorem1直接当作完整模格QROM定理。沿用[前轮条件/成本复核](../2026-10-09-admission/README.md)，模拟/分叉适配仍为条件 |
| 算法参数与当前精确q | 原稿Table1不提供当前精确q，实际κ也已重选；使用既有整除/NTT/Hint及MSIS/MLWE筛查，不继承作者位数。成本模型不能当总体IBS证明 |
| 持久缓存/格式 | 固定身份、规范长度前缀/域分隔、主状态和私钥加载方程已实现；本轮补齐并发、快照、发布和固定profile。MODULE-REF/COMPACT wire不变 |
| Wang组合及BYTEAUTH | 身份顺序(rcv,phi)、接收者+envelope的签入、完整签名载荷保持；Byteauth/KEM-DEM的条件按既有报告分项引用，不能由Luo论文直接授予全部篡改拒绝或CCA |
| 两层匿名HIBE | 当前仍ABB10教学后端，CHKP未交接；这是首套安全准入的独立阻塞，本轮未用mock代替它 |

**当前决定：保留Luo模格为首套待集成的可执行研究基线；状态/配置实现缺口已修复，论文条件和整体安全准入继续明确保留。** 没有以绿色测试、锁或成本数值提升安全声明。

## 3. 参数与测试范围

Luo配置保持N=256、(k,l)=(11,10)、q=274877844481、root=153250464611、η=1、κ=64、γ1=125440、γ2=31470387200、γ3=15270991360、d=28；身份≤64 B、IBS消息≤4096 B、Extract/Sign各1024次。线程单元另用N=8、(k,l)=(2,1)、q=769、root=27、κ=1、γ1=16、γ2=256、γ3=128、d=3的教学配置，不从该例推断安全。

HIBE仍为n=8、m_matrix=168（m_bar=16）、q=524288、s0=3、s_enc=s_pre=1、编码身份86 B和种子32 B的教学配置。应用上限3924 B、两种签名格式及哈希输入不变。参数来源是前轮研究选择，无新增攻击成本计算、生产参数或安全等级；全部none/false。

新增28项：10项OS锁/失效检查，18项真实状态/参数/线程检查。并发试验包含同身份、不同身份、接收者与发送者混合，各1次强制交错；两种线程操作各1次。另有发布失败注入、安全重试、进程终止释放、另一合法q配置及配置切换覆盖拒绝。私有向量、快照和测试密钥仅在pytest临时目录，不导出到报告。

复用旧模块契约、reference/compact完整协议和旧CLI回归，分别核对真实签验、恢复、四种匹配、公开新格式伪造、持接收密钥重签、篡改与非法输入。测试不替代安全证明。结果、命令与环境由admission.json记录；初始10项反例及随后配置预检1项回归失败均已注明。

最终新28项检查跨Windows/WSL通过；状态/模块组75 passed、reference/compact完整协议组46 passed、最终Setup兼容组3 passed，每个环境共124个不重叠检查。此前旧CLI选择12 passed，与最后3项有重叠，不追加计数；最终无失败、无XFAIL或跳过。初始新增反例为10 failed/1 passed；完整协议初版各环境45 passed/1 failed，预检修复后完整46项已重跑通过。

环境：Intel Core Ultra9 275HX；Windows Python3.14.6/pytest9.1.1/cryptography49.0.0；指定WSL Sage10.9/Python3.13.14/pytest9.1.1/cryptography49.0.0。JUnit统计及哈希由实际XML读取，代码/测试LF指纹与源PDF/前轮参数筛查指纹同时记录。未导出实际主/用户密钥。

```text
python -B -m pytest -p no:cacheprovider -q --tb=short tests/test_cli_state_lock.py tests/test_research_state_integrity.py tests/test_luo_module_backend.py
python -B -m pytest -p no:cacheprovider -q --tb=short tests/test_luo_hybrid_ibme.py tests/test_luo_compact_ibme.py
python -B -m pytest -p no:cacheprovider -q --tb=short tests/test_baseline_ibme.py tests/test_byteauth.py -k "cli_setup or cli_usage or default_cli"
wsl -- bash -lc "cd /mnt/d/zcode_projects/ibme && ~/miniconda3/envs/sage/bin/python -B -m pytest -p no:cacheprovider -q --tb=short tests/test_cli_state_lock.py tests/test_research_state_integrity.py tests/test_luo_module_backend.py"
wsl -- bash -lc "cd /mnt/d/zcode_projects/ibme && ~/miniconda3/envs/sage/bin/python -B -m pytest -p no:cacheprovider -q --tb=short tests/test_luo_hybrid_ibme.py tests/test_luo_compact_ibme.py"
wsl -- bash -lc "cd /mnt/d/zcode_projects/ibme && ~/miniconda3/envs/sage/bin/python -B -m pytest -p no:cacheprovider -q --tb=short tests/test_baseline_ibme.py tests/test_byteauth.py -k 'cli_setup or cli_usage or default_cli'"
```

## 4. 文件和下一步

本轮跨CLI、IBS、协议读取器、测试和规范，是为了落实同一固定用户状态与配置；没有修改队友CHKP/格工具、原语数学算法或协议签入内容。共14个文件，完整修改清单在admission.json中。

下一项仍优先接CHKP真实单体与参数/契约交接，合格后跑首套完整攻击验收。交接未到时推进首套HIBE接入规格与必要协议条件，避免再次转回备用候选深挖。已向用户询问队友实际进度；本仓库未收到不等于队友未在本地工作。

WIP：正式HIBE、合法安全参数/完整引用适配、首套安全准入、QROM/侧信道与硬断电多文件一致性；旧education两个认证反例仍未关闭。研究对象保持security_claim:none/backend_admitted:false。
