# AR：三个 HIBE 储备的模型、缺口与有限成本

本批完成A任务书的储备说明，不编码或登记GKR/ABB-standard/CHKP-standard后端，也不改变首批顺序。依据三份已归档原稿逐页核验，[来源指纹](sources.json)固定其版本；[有限对象计数](costs.json)由 `experiments/research/abb_rom/reserve_costs.py`重算。全部是原文结构及指定格式下的算量，不是执行/性能/安全参数。`security_claim=none / backend_admitted=false / parameters_are_formal=false`。

## 模型差异与第一缺口

| 储备 | 可引用原文入口 | 与现主线的差异 | 第一项未完成模块 |
|---|---|---|---|
| GKR 2025 匿名LWE路径 | 34页稿PDF14–16 §3.1/Theorem3.1；PDF32–34 AppendixB/TheoremB.1 | §3通用编译器只给自适应HIBE；匿名LWE扩展另加lockable obfuscation。CDH的blind-IBE/garbling路线独立，不能替换为LWE标签 | 可执行且带有限参数的lockable obfuscator及完整HIBE.Dec电路；同时缺OTSE/PKE/garbling/可委派PRF具体实现 |
| ABB EUROCRYPT 标准模型HIBE | 40页全文PDF32–34 §8.2、式(22)、Theorem33 | 明确结论为INDr-sID-CPA，即选择身份、密文不可区分于随机；§7自适应结论针对IBE。不能升格为Wang自适应HIBE | 全秩差映射H及不同维度的SampleBasisLeft/Right、关联噪声；另缺被引用覆盖的自适应/匿名模型转换 |
| CHKP 标准模型SMHIBE | 36页作者全文PDF26–29 §5.4.3–5.4.5、式(5.3)、Theorem5.4/Corollary5.5 | 不经§5.3矩阵RO，改为admissible hash选择公开块；完整安全依赖有限Delta和KEM。§5.2跨层匿名padding另核 | 具体admissible hash、输入域/输出长度/有限Delta；其后是扩展RandBasis/固定解封装原像/独立参数与wire |

以上不是“论文结论不成立”。原文给出理论构造；缺的是本项目选定实例、前提对应和实现。已有ABB-ROM及CHKP-ROM的源码、参数或通过记录不能借给标准模型变体。全秩差映射不是把任意bytes丢给SHAKE；admissibility也不能由抗碰撞散列的函数名推得。

## GKR：有界输入的有限账本

为估量两层86 B边界，先提出一个**未冻结**的编码：每层 `role1 || LP4(identity)`。两层最长二进制路径L=1456 bit；委派按第二层完整有序编码追加，不能让层间拼接产生前缀歧义。

§3.1算法按含root的端点计数：KeyGen含L+1=1457个Node；每个Node包含3个OTSE.Setup、1个PKE.Setup、1个OTSE.Sign及PRF求值/委派。密文生成含L+1个Q和1个T，共1458个garbled circuits；每个Q的电路体包含2·lambda个OTSE.Enc。正文效率段省略端点的渐近n记法不直接当有限计数。以论文便捷约定vk/pk长度lambda=128 bit示例，链中的3lambda-bit消息材料共69936 B，尚不含签名、PRF/PKE私钥、garbled gate/labels或外层codec。

这些是通用HIBE编译器的材料计数，**不是匿名LWE密文的最终尺寸**。AppendixB每次Enc额外加密随机lock alpha，并将绑定该ct_alpha的Dec电路交给Obf；最终密文是obfuscated program，大小取决于选定LO的门数/深度/参数。其具体byte/time/TV全部unknown，不能填一个“预计几KB”。两层身份边界和256bit载荷使所需电路有限，并没有给出可用的有限常数或现成实现。

重启条件：冻结OTSE的真正五算法（普通OTS不能替代）、自适应可委派PRF定义和输入编码；选定各底层算法/论文版本/许可证；实际实现并核LO.Obf/Eval/Dec电路；交每类gate/label/密钥/密文尺寸和资源上界，随后走六方法、固定发钥与攻击契约。若只实现§3的非匿名编译器，单列教学/模型对照，不能作为Wang匿名HIBE交付。

## ABB 标准模型：扩展格和关联噪声

§8.2在深度ell的F_id有(ell+1)m列；两层根/父/叶完整基分别m、2m、3m维。d=2时公开材料有4个n×m矩阵及n-vector u。每bit密文有3m+1个模系数；256独立bit重复时是256(3m+1)个系数。

原Encrypt另外抽m×ell·m个Rademacher符号，产生z=R^T y；两层每bit有2m²个符号，256bit为512m²。它与独立Gaussian y相关，**不能复用ABB-ROM中全部分量独立的噪声向量**并仍称原文算法。有限取整噪声、宽度和正确性须按这一结构重算。原文sigma/alpha/omega还没有本项目认可的有限取值。

仅做尺寸试算：n=128、q bitlength61、m=6·128·61+1=46849，未满足/核验式(22)全部条件，不对应128位安全。根/父/叶为46849/93698/140547维；若沿用A当前逐entry最少6 B的signed格式，分别至少13.17/52.68/118.52 GB（不含头）；256bit模系数约287.84 MB。其它压缩/表示须重算，不能把这个格式条件下的估算说成所有实现的信息论下界。现Matrix工具1536维域、Hybrid4MiB capsule和16MiB component均不支持该试算对象。

重启条件：先确定本路线仅作选择性比较，或找到符合主线模型的明确转换；冻结H:Zq^n→Zn×n全秩差编码；给SampleBasisLeft/Right的论文—宽度—有限实现表；根父叶同组q/sigma/alpha/关联噪声合法性、正式攻击估计、可用完整基表示和资源测试通过后再写backend。不得把参数变体算作新算法，也不得引用§7自适应IBE替代§8的HIBE模型。

## CHKP 标准模型：hash位数直接乘进格维度

式(5.3)给根/ell层维度(1+ell·h)m，其中h是admissible hash输出位数，不是直接取“128位安全”的数字。两层公开矩阵数为1+4h，叶维度(1+2h)m；身份hash实现、实际h和有限Delta尚未选定。原稿已知构造的渐近h=O(n_H^(2+epsilon))没有提供可直接代入的有限常数，n_H的hash输入域与格维n_L应分别记录。

同样的尺寸试算n_L128/qbits61/m46849，加**仅用于比例观察、未获admissibility准入**的h256：公开矩阵材料约49.17 GB；父/叶为12040193/24033537维。逐entry6 B假设下，叶基约3.47 PB。成本表另列h128和16384两点，它们不是执行preset。§5.2匿名padding需填到固定最大维度，再按§5.1共享前导多bitKEM核计；不能把ROM的3m前导和宽度直接照搬。256bit标准模型适配还须定义公开的独立target列及固定原像，表中矩阵材料未包含这些附加target；不能照搬当前ROM的G(id,i)并仍称标准模型。

Theorem5.4的归约分母为Delta(n_H,Q)^d；已有Delta=Theta(Q^-2)构造在d2给Theta(Q^-4)，需保留有限常数、admissibility碰撞项、模拟误差及参数估计；这不是运行中止概率。固定两层避免无界深度的损失，并未消除hash位数带来的对象爆炸。

重启条件：取得并实现被引用的具体admissible-hash构造，核hash输入域/输出位数、固定查询预算与有限Delta；选择n_L/q/m/宽度/噪声同组profile，解决矩阵/基表示和固定原像实际域；分别核标准模型游戏、匿名padding及Wang组合前提，后续才做真实原语与组合验收。SHAKE不能通过关掉一个ROM开关自动成为这条后端。

## 验证、限制与交接

来源是本地固定稿：[GKR](../../../../papers/2025_adaptive_hibe_goyal.pdf)、[ABB标准模型](../../../../papers/2010_lattice_hibe_standard_agrawal.pdf)、[CHKP作者全文](../../../../papers/2010_bonsai_trees_cash.pdf)。来源索引记录SHA/页数及原文锚点，已核关键算法与定理段，不复证基础归约。计数脚本只算整数，不创建矩阵/密钥或消耗熵；可在普通Python运行。

```text
python experiments/research/abb_rom/reserve_costs.py --output test-results/a-reserve-costs.json
python -m pytest -q tests/test_a_matrix_reserve_costs.py
```

计数检查 **7 passed**，独立手算小维度对象、root/最终电路端点和非法输入；[JUnit](counts.junit.xml)。AR说明交付完成；三个完整储备backend仍未实现/未登记，预算与模型不能满足时继续保留comparison/reserve。下一主编码仍是ABB-ROM真实纵向闭环和对应接入，原CHKP复用队友PR；统筹选代表时不得将这些计数卡加入“已实现后端”数量。功能与计数核对不能替代安全证明。
