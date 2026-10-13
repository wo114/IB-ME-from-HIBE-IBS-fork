# A2：ABB-ROM 公开研究后端、固定状态与纵向实跑（WIP）

本批接 A3 `0a9e512`。新增六方法后端、五类严格对象及独立登记提案，不修改公共 registry、协议或 CLI。完整正条件配置的父/叶与32 B闭环尚未通过，不能把接口或夹具测试算成完整 ABB/IBME 实现验收。保留 `security_claim=none / backend_admitted=false / parameters_are_formal=false`。

## 原文与代码

| ABB10 原文 / 有限工程约定 | 实际入口 |
|---|---|
| §4.1 Setup、AP09 Algorithm1/§3.3 根族 | `ABBROMHIBE.setup → abb_trapgen`，真正的独立均匀A1/三元R/完整整数基；不换MP12根 |
| §3.1 SampleR | 全矩阵IID离散Gaussian，只在模q奇异时整体重抽；有限尝试/ABORT。宽profile采用精确PARI模行列式 |
| §3.1 BasisDel / 全格补全 / RandBasis | 真正R·T、目标A·R^-1、完整格ToBasis和独立RandBasis；原子格不冒充目标完整格 |
| §4.1 Extract / Derive | H(rcv)、H(rcv,phi)依次变换；根/父/叶固定维度，独立sigma1/sigma2；固定地址缓存和失败标记 |
| §4.1 原始bit Encrypt / Decrypt | 每bit新s及m+1个取整连续Gaussian；每bit新SamplePre，MSB序，原整数阈值；方程和范数失败中止整次，无部分载荷 |
| 公共编码与绑定契约 | PK/MSK/SK1/SK2/CT五codec；完整参数/角色/公钥/有序私有路径/维度/规范整数/缓存/截断/追加/重复/预算 |

公开CT只有版本、完整参数、公钥上下文、长度与bit块，没有身份或公开枚举身份标签。私钥恢复核完整格、目标身份矩阵及公开GS界；这不能证明该密钥的采样来源。基础CPA错身份可解出其它bytes，Hybrid/IBS负责认证拒绝。

矩阵H的论文模型是矩阵随机预言机；SHAKE分块公开tape→有限SampleR是明确工程实例，**未证明相应indifferentiability**。公开分布证书假定独立均匀bytes，不能直接给SHAKE实例套用ROM定理或安全等级。

`ABBROMParams`是独立精确整数配置，拒绝旧Params隐式转换、未知/缺失/重复/非规范JSON及安全标记升级。所有输入重新计算同组条件；known public blockers、最小主密钥wire和完整SampleR预算在Setup私有熵前检查。bit噪声的tail/mass/precision/uniform现显式读取该完整配置。

## 固定地址与恢复

每个父/子地址先记FAILED/PENDING再进入采样，成功保存唯一密钥，失败保留标记；重调用/恢复不重新发钥。缓存的当前地址、公钥和路径在读取和序列化时重新检查，修复了原WIP中可错换缓存地址的问题。可选 `persist_pending`单写者回调在发钥熵前写规范状态；它不是跨进程事务或多机锁。统筹的commit-before-publish策略仍须由外层实施。

新 `experiments/research/abb_rom/hibe_probe.py`只对新目录生成一实例，阶段前写pending，实际主状态只保存在 `master.bin`；采样前原子写失败地址，异常/SIGINT后仍保存该状态。声明RSS观察预算，超过预算请求SIGINT并保留pending。观察器不是Sage分配器的形式化内存保证。`--restore-only`只允许复用已经出现的固定/失败地址，不执行新发钥；ABB原文每次Decrypt仍要求新SamplePre，故恢复检查不冒称零熵解密。

## 同组配置与已发生的结果

| 项目 | n1/q160/m1280 | 新选择 n1/q104/m832 |
|---|---:|---:|
| AP09 d/m1/m2/Cprime | 320/320/960/56 | 208/208/624/46 |
| SampleR平方宽度 | 623798000 | 277673628 |
| sigma1² | 19480480075862507520000000 | 1623986518409894312214528 |
| sigma2² | 436067107841351475394815841680752640000000000000 | 4393678979852224267713637199190156629954789376 |
| tau2² | 312572902900680737563003995316763492352000000000000000 | 2032480746647800128450186859247772935764045927022592 |
| 内部身份/载荷 | 各86 B / 32 B | 各86 B / 32 B |
| 公开条件噪声充分界 | true | true |
| 32 B原始CT尺寸 | 约6.56 MB，超过Hybrid4MiB | 约2.77 MB，预检容量通过 |
| 实際Setup | 一次通过 | 待本批纵向实跑 |
| 实际完整生命周期 | 未通过 | 尚未通过 |

q160真实Setup一次：30.964 s，PK26686 B、MSK9858221 B，峰值RSS613232 KiB，系统随机源。其父发钥使用旧WIP3 B身份Bob，1325.745 s后以观察预算中断，峰值RSS9732540 KiB，FAILED地址保存；新进程实际恢复及禁止重发测试通过。原Setup/父程序在本批最终源码之前执行，保留当时指纹，不称最终代码实跑。最后native栈位于FLINT完整整数HNF/行列式求解；先前也观察到宽GF消元。中断请求中的早期“wide-field”描述不是最终HNF定位。私有熵总数当时未计数，记unknown，不补造零值。

另一次只用公开PK和H(Bob)的原1280维整矩阵Gaussian做PARI算术实测，472 s内完成模行列式与逆，并独立核两侧整数模方程；峰值RSS1219792 KiB，公开tape682916242 B、私有熵0。它没有发钥、HNF或HIBE闭环，不与旧父过程混算加速比；其起始完整源指纹未捕获，作为有限算术观察记录。

公开选择表同时筛过n1的72/80/88/96/100/104/112/120/128/160位模数及n2的88/96位。低模数的噪声失败和高模数的4MiB容量失败均保留，未选失败配置进行完整加密。新q104是预先声明的新实例，只有1父/1子容量；不重抽或解除q160旧Bob失败地址。研究root的统计距离、采样epsilon、噪声条件和难度分别记录，不拼接通过项。

精确实现改动：wide模逆由PARI计算并核左右逆；wide ToBasis固定使用Sage `padic/proof=True`得到同一唯一row HNF，仍核T·R=S及完整格；GPV投影和固定normalizer以native QQ向量点积代替逐项Python有理数和，决策/输出/随机tape不变。旧有限硬边界仍在，固定源差分、奇异全矩阵丢弃、原格补全和正常化输出比较通过。Sage/库内部资源失败未获总概率界，Matrix SampleR的总失败与成功条件化TV字段据此为null；rank/scalar界单列，不能默认缺项为零。

## 测试与交接

最终本批源码Sage **221 passed / 3 skipped**；缺两个旧native私有witness和一个旧84维witness，skip不当pass。Windows **137 passed / 8 Sage依赖skip**。两批重叠，不求和。状态夹具明确用公开代数/发钥消费者instrumentation；它们证明缓存/恢复/包装控制，未替代真实BasisDel。既有原始算法、标量分布统计和单源兼容回归也包含在Sage批次。

证据：[审计与准确测试命令](audit.json)、[Sage结果](sage.junit.xml)、[Windows结果](windows.junit.xml)、[实际Setup](positive-setup.json)、[父中断](interrupted-parent.json)、[公共算术观察](public-modular-observation.json)、[完整公开选择表](compatible-profile-screen.json)、[新实例完整参数](selected-q104-params.json)。历史未提交WIP源码可由本提交源码加[重建差分](execution-source-reconstruction.patch)恢复（`git apply --unidiff-zero`，仅在独立复制目录使用）；已逐文件核到执行收据的原SHA。实际私钥、矩阵、运行状态、原始native栈均在ignored目录，不提交。

`backend_spec()`给独立 `abb-rom-finite / abb-rom-ap09-matrix-finite-v1`，factory、完整参数读取、四私钥/公钥decoders加CT加载、实际尺寸函数和绑定/固定状态能力。`ABBROMParams.identity_bytes/max_message_bytes`只提供公共容量别名，不转换旧参数。缺Sage显式unavailable，没有mock回退；available仅表示可调用研究代码。没有默认注册。新profile的容量预检不证明私有状态总wire/RSS必然可行，需实际测量，尤其Hybrid单个component仍有16MiB限制。

队友CHKP由PR #14固定head `87deec24f52c1c776a489566cf76f11d0d4a5aff`交付，其n2研究配置公开攻击成功；本批没有重复编写或改其文件，统一合入与复核归统筹。A1 MP12变体与原CHKP继续分别命名。

可执行命令（源码目录；实跑必须新私有目录，提交SHA由宿主取得）：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.abb_rom.hibe_probe \
  --private-directory test-results/abb-q104-new/private --baseline-commit <40位SHA> --max-rss-mib 8192

PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.abb_rom.hibe_probe \
  --private-directory test-results/abb-q104-new/private --restore-only
```

WIP：q104真实父/叶与256 noisy bits、完整Hybrid+Luo组合攻击、正式高n工具/估计/模型映射、AR储备章节尚缺。本批不能放行正式后端或三个代表。n1是困难性负控；测试不能代替LWE/HIBE/IBME安全证明。
