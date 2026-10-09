# Yu 2026：同态代数、匹配电路与队友可复用单元

日期：2026-10-10；基点 `f6c626e`，其 GitHub CI run37965342390已成功，远端没有新增提交或PR。本轮继续全候选基础工作，选择Yu独立IBS中的一个具体依赖单元；没有继续压缩或密码性能跑分，没有修改队友CHKP或生产接口。

**已交付可运行的gadget位分解、NAND电路、公开/私有整数求值和匹配函数。** 47项检查跨Windows/指定WSL Sage通过，Sage独立核对32组全部输入、152次位原像及32个篡改输出。代码在 [homomorphic_reference.py](../../../experiments/research/candidates/yu/homomorphic_reference.py)，独立核验在 [audit.py](../../../experiments/research/candidates/yu/audit.py)，完整公开结果见 [audit.json](audit.json)。

本轮只完成Lemma7的**同态代数关系参考**；尚未核验其完整奇异值增长保证，也没有真实PRF、陷门采样、发钥/签名或IBS后端。全部 `security_claim: none`、`backend_admitted: false`，不计新增完整算法/组合实例。

## 1. 原文与实现对应

使用用户提供的26页出版稿 [Yu–Liu–Li](../../../papers/2026_ibs_ibme_yu.pdf)，SHA-256为 `f10d8672d952d9923a00c883a7d65feb36a15fb67fbef1c52ee64254f5301948`。参数和符号锚定以下位置：

| 原文 | 本轮入口与范围 |
|---|---|
| §2.2 Definition2，PDF6 | `Params`、`gadget`；二进制gadget，$w=n\lceil\log_2q\rceil$ |
| §2.2 Lemma7，PDF6 | `eval_public`、`eval_private`、`homomorphism_holds`；实现精确整数/模关系，不继承整个范数结论 |
| §3.3 Eq.(3.2)，PDF11 | `matching_circuit`；公共匹配向量对应的相等判断，编译为平衡NAND电路 |
| §3.3 Figure5，PDF12 | 说明这个基础供身份PRF/消息PRF及其输出匹配求值使用；本轮未实现Figure5四算法 |

令输入位为$x_i$、整数见证为$R_i$，公开输入满足

$$A_i=AR_i+x_iG\pmod q.$$

Lemma7声明输出接口与关系

$$A_C=AR_C+C(x)\otimes G\pmod q.$$

多输出的掩码明确采用水平拼接$[C_1(x)G|\cdots|C_k(x)G]$，与$n\times kw$的输出形状一致。原文还声明所选求值算法的奇异值条件。本项目不能从上式成立就认定该条件满足。当前独立参考采用规范二进制位原像：$D_j$每个条目为0或1，按gadget的低位到高位排列，满足$GD_j=A_j\pmod q$。它不是高斯原像采样器。

## 2. 当前NAND参考的明确计算

我们选择以下代数实现作为可执行基础，不声称论文逐门给出了这些代码，也不将其视为完整Lemma7实例：

$$A_{\mathrm{out}}=G-A_LD_R\pmod q,$$

$$R_{\mathrm{out}}=-R_LD_R-x_LR_R,\qquad x_{\mathrm{out}}=1-x_Lx_R.$$

展开第一式：

$$G-(AR_L+x_LG)D_R=A(-R_LD_R-x_LR_R)+(1-x_Lx_R)G\pmod q.$$

因此每门保留同态关系。多输出按原文水平拼接，输出顺序保留；共享线、重复输入和匹配电路均有独立真值对照。

`eval_public`只接收电路、A及公开输入块；`eval_private`接收位和整数见证。二者没有全局密钥目录/隐藏输入，构造和求值不修改调用对象。输出见证保留符号与完整整数值，不先模q；对象repr隐藏见证内容。输入/输出见证只在实验内存中，结果不保存这些矩阵、其摘要或测试随机种子。

## 3. 范数、条件和资源边界

设初始见证的最大系数绝对值为$T$。规范位原像是宽为w的0/1矩阵，因此每门有可直接核对的保守系数界：

$$\|R_{\mathrm{out}}\|_\infty\le w\|R_L\|_\infty+\|R_R\|_\infty.$$

输出深度为D时，本参考记录并检查

$$\|R_C\|_\infty\le T(w+1)^D.$$

Sage另检查由该界得到的Frobenius平方界。这是本参考的保守整数关系，**没有证明它满足原文的$O(4^D m^{3/2})$奇异值保证**，不能将它直接代入Theorem3而省略范数适配。`norm_profile`和结果中的`paper_spectral_norm_bound_verified`明确记录未核验状态。

初始$R_i$为±1的实验符合Lemma7这一输入条件；组合第一层结果再做匹配时，新的整数见证通常不再为±1。组合代数已验证，原Lemma7的输入/范数范围仍须重新对应，代码保留`input_pm1`标志而不静默升级声明。

研究预算固定：1–4行、1–16主矩阵列、奇数模数3–65537；最多32输入、256门、16输出、深度16，单个整数系数最多512bit，规范电路描述最多65536 B。所有公开系数要求在$[0,q)$；矩阵维度、拓扑顺序、类型、输出索引及规范JSON严格检查；资源超限抛异常，不返回部分结果。

这些是执行上限，不是正式SIS参数。实验允许复合模数81以检查模运算；Yu整套实例还依赖Lemma6等其它条件，本轮没有认定复合点符合其安全要求。匹配函数匹配的是PRF输出的比特向量；本轮2/3/4位示例尚未接真实身份、消息或Wang协议。

## 4. 实际实验与负面对照

| 用例 | 参数 $(n,m,q)$ | gadget列w | 门/输出深度 | 全输入数 |
|---|---|---:|---:|---:|
| 单NAND、素数 | $(1,3,17)$ | 5 | 1 / 1 | 4 |
| 单NAND、复合模数 | $(1,3,81)$ | 7 | 1 / 1 | 4 |
| 共享线和三输出 | $(2,4,257)$ | 18 | 2 / 2 | 8 |
| 匹配向量1010 | $(2,4,257)$ | 18 | 8 / 5 | 16 |

每种输入一次，均保留。测试流是显式教学固定流，初始见证为±1；没有Gaussian或PRF安全实验。Sage重新建立gadget和所有位分解，独立计算每个公开NAND输出及最终矩阵关系；不只调用参考自己的关系检查函数。

每组公开输出修改一个规范系数，32次关系检查全部拒绝。另保留一项负面对照：将整数见证模q化，仍能满足模方程，但改变了整数见证，并可违反其原系数界。方程通过不能认证范数或分布。测试也覆盖公共输入不受另一私有见证选择影响、原始位/矩阵篡改、两个阶段组合、规范电路往返、重复字段、版本、畸形尺寸/范围、非法拓扑和资源耗尽。

## 5. 环境、测试与复现

硬件Intel Core Ultra9 275HX。Windows Python3.14.6/pytest9.1.1：47 passed；指定WSL conda Sage10.9/Python3.13.14/pytest9.1.1：47 passed。没有XFAIL。原语安全和正式参数不能由这些测试推出；本轮无计时加速或NIST等级结论。

加上候选基础回归：Windows执行`tests/test_candidate_foundations.py tests/test_yu_homomorphic_reference.py`，71 passed；WSL再加入`tests/test_candidate_preflight.py`，84 passed。批次有重叠，不累加为新增原语数量。

```text
python -B -m pytest -p no:cacheprovider -q tests/test_yu_homomorphic_reference.py
wsl -- bash -lc "cd /mnt/d/zcode_projects/ibme && ~/miniconda3/envs/sage/bin/python -B -m pytest -p no:cacheprovider -q tests/test_yu_homomorphic_reference.py"
wsl -- bash -lc "cd /mnt/d/zcode_projects/ibme && PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -B -m experiments.research.candidates.yu.audit --output test-results/yu-homomorphic-audit.json"
```

## 6. 交接与下一项

队友可直接使用这个独立目录的电路/位分解/代数测试作为输入/输出的检查基础。新增规范电路格式仅用于研究图，不是新IBS签名或密文格式；进入正式原语前仍须冻结参数与编码，并完成同等契约及攻击验收。没有跨入队友HIBE/采样文件，也未改生产随机数、签名哈希或协议语义。

Yu路线下一项：选定实际PRF及其有限电路/公开私有求值；提供适合所引用范数条件的求值实现或明确有限对应；之后接GenTrap/DelTrap/RandBasis/SamplePre和Figure5完整单体。直接引用原文，不把这里的粗界当完整归约，也不默认重做整个标准模型证明。

全候选主线继续保留：首套CHKP+已有Luo仍待HIBE交接；下一轮可推进SRGG的公开关系/协方差最小单元，形成与Luo不同采样路线的实际比较基础。三组代表仍按完整数据选择，优化后置。

修改文件：本研究目录的两项代码、`tests/test_yu_homomorphic_reference.py`、本报告/公开audit；候选catalog/生成卡、README/项目记录/主AI工作单和CI更新进度。WIP：真实PRF、所需范数保证、Yu四算法及完整组合未实现；默认education两个认证反例不因这项基础修复。全部none/false。
