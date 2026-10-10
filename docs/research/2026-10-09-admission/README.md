# M2-B3：Luo 模格的 MSIS/Hint 界、成本和条件准入复核

日期：2026-10-09；基点 `e7d9405`；远端无新增提交、无待合并 PR。主 AI 本轮只做参数/引用复核、独立算术检查及固定工具的成本估算，不改 HIBE/IBS/协议算法，不改消息/身份输入，不修改队友文件。

**决定：保留 Luo 模格方案及当前 κ=64 的研究输入，继续工程实现；本轮没有理由再盲目扩大 q 或退回已被初筛排除的矩阵参数。** 算术与明确列出的 128 指数启发式筛查通过。正式安全发布仍 `security_claim: none`、`backend_admitted: false`：论文模拟/分叉条件、实际量子及实现模型、正式 HIBE 等不能由这份成本结果替代。

完整输入、源指纹、各成本字段及 144 个固定扫描点见 [module-security.json](module-security.json)。当前真实运行入口仍是 [M3-A](../2026-10-09-hybrid/README.md) 的 `luo-module-research`，其 HIBE 仍教学。

## 1. 引用位置与本项目解释

原文为 [Luo 等 ICICS 2024 固定稿](../../../papers/2024_ibs_without_trapdoors_luo.pdf)，[公开稿](https://icics2024.aegean.gr/wp-content/uploads/2024/08/150570198.pdf)。使用范围如下。

| 原文位置 | 本轮核验及限制 |
|---|---|
| §4.1 Definition 5，PDF 第 11 页 | MSIS 是非零整数多项式向量、系数无穷范数界、模 q 核关系；不能把模块维度 k 直接当系数维度 |
| §4.1 Algorithms 7–12 | 用任意合法 Hint 的公开恢复结果构造 u，覆盖 q−1 与高位回绕；不只核对诚实 Hint |
| §4.4，PDF 第 15–16 页，式 (4.1) | 恢复低位后额外出现 u′；明确每个响应块的范数及 [A\|I] 维度 |
| §3.2 Theorem 1 的 E / E′ 分支，第 9–10 页 | 作为模格草图的分叉结构入口；本轮代入扩展响应和相应矩阵，不直接套旧矩阵的参数与界 |
| 第 9 页缓存、Algorithm 6 | 沿用 R1 的共享有状态 Extract Oracle 解释；模拟器、编程失败与分叉成功率仍按原文声明的条件引用 |
| Table 1 | 保留维度/掩码来源，不继承作者安全位数；本项目精确 q、γ₃、κ 与表格不同 |

§4.4 最后一行将 H(w₁,id) 简写为 H(w,id)。实现仍按 Algorithms 14/16 对 **Power2Round(w)** 的规范高位编码调用 H1。本轮把它解释为复合函数 H1(Power2Round(w),id)，没有改成对完整 w 重新哈希，也没有假定每个不同低位升举获得独立随机预言机回答。

本轮额外给出的分支代数与有限非零论证是项目的**条件式对应解释**。它明确依赖原文宣称的公开模拟、相同目标哈希输入和分叉事件；不是声称作者提供了本文所有细节或本项目已补完整个 QROM 归约。

## 2. 实际参数与压缩误差

研究输入保持不变：N=256、(k,l)=(11,10)、q=274877844481、NTT 根153250464611、η=1、κ=64、γ₁=125440、γ₂=31470387200、γ₃=15270991360、d=28。β₁=64、β₂=8028160；身份上限64 B、IBS 输入上限4096 B、Extract/Sign 各1024次。

设 v=Az−(w₁·2ᵈ+t·CID)c，α=2γ₃。对任意合法 h，可以取中心化整数 u，使 `α·UseHint(h,v) ≡ v+u (mod q)` 且 `||u||∞≤α+1`。r=0、h=1 的回绕恰好需要 −(α+1)，不能漏掉 +1。

当完整 w=w₁·2ᵈ+w₀ 时，u′=u+w₀c；论文界及实际值为：

| 量 | 当前值 |
|---|---:|
| 实现严格响应 z 最大绝对值：γ₂−β₂−1 | 31462359039 |
| 身份响应 Z 的界：γ₁−β₁ | 125376 |
| 丢弃低位乘挑战：κ·2^(d−1) | 8589934592 |
| Hint 校正：2γ₃+1 | 30541982721 |
| 恢复误差 u′：κ·2^(d−1)+2γ₃+1 | 39131917313 |

误差块比 z 块更大，因此不能仅用 γ₂ 做全见证筛查。各范数为**整数负循环多项式系数范数**，不是模 q 的非负代表元范数或欧氏范数。

公开升举也检查了最高端：w₁=1024 时，选 w=q−1 对应 w₀=−62464；若直接取 1024·2²⁸ mod q 再令低位零，其 Power2Round 会变成0。新的核验按公式计算，避免抄写常数。该角点没有改变既有原语算法。

## 3. 两类分叉见证和维度

记 M=[A|I_k]，x=(z,u′)，固定身份密钥 Z=(z₁,z₂) 满足 MZ=w+t·CID。假定分叉给出相同 H2 输入及目标 w₁。

**已签身份分支：**相同 CID，挑战 c≠c′。关系给出 `M·(x′−x−Z(c′−c))=0`。精确块界和原文风格的放松界分别记录，后者取 γ₂/γ₁ 而不减严格边界裕量。

**新身份分支：**在 MLWE 将 t 替换为均匀的混合之后，相同 c、不同 CID/CID′。关系给出 `[M|t]·(x′−x,−(CID′−CID)c)=0`。这里不能遗漏 t 这一整块；末块系数 ≤2κ=128。

| 筛查行 | z 块界 | u′ 块界 | t 块界 | 系数矩阵尺寸 |
|---|---:|---:|---:|---|
| 已签身份精确界 | 62940766206 | 78279882754 | — | 2816×5376 |
| 已签身份保守界 | 62956830720 | 78279890946 | — | 2816×5376 |
| 新身份扩展矩阵 | 62924718078 | 78263834626 | 128 | 2816×5632 |
| 两分支共同放松输入 | 62956830720 | 78279890946 | 128 | 2816×5632 |

工具仅支持单一无穷范数界，所以每行以**最大块界**放松全部坐标；完整矩形块约束另外记录。这是更宽的搜索域，未当作已实现的具体 IBS 伪造。共同界78279890946小于(q−1)/2，未触发 q 倍单位向量的平凡门槛。

[A|I] 是规范化结构，Definition 5 给的是均匀矩阵。对完整均匀挑战矩阵取最后 k 列的可逆块 B，左乘 B⁻¹ 得到 [B⁻¹A|I]，原核见证坐标保持不变，无范数膨胀；新身份同样保留随机 t 列。N=256、q 为已验证的分裂素数时，坏块概率的简单上界为 N/(q−1)。条件于可逆块得到目标均匀分布，归约损失是该成功概率的**乘法因子**，不把约2⁻³⁰当作直接加到 IBS 优势上的误差。独立 Sage 示例验证该归一化代数，不用少量样本声称分布证明。

## 4. 非零见证：可以明确的两项条件

新身份的末块为 c(CID−CID′)。N 为二次幂时，Z[X]/(X^N+1) 是整环；c≠0 且 CID≠CID′ 保证整数乘积非零。该乘积每个系数的绝对值 ≤2κ=128<q，故不可能全部变成零模 q。这里**不需要**错误假设所有稀疏挑战在 Rq 可逆；Rq 本身可以有零因子。Sage 验证当前分圆多项式不可约，并对小空间乘积独立枚举。

已签身份仅 c≠c′ 不足：两份诚实响应用相同掩码时，`x′−x−Z(c′−c)`可以恰好为零，测试保留该反例。给出非零概率条件需要原文的模拟：目标 Z 在界125376的5376维整数立方体中均匀，公开视图除 w₁ 标签外可由独立公共随机性模拟。w₁ 有2816个系数，每个最多1025个值。

在该条件下，整数环中任意非零乘子的乘法是单射。攻击者看标签后选择乘子和目标，每个标签/每次尝试至多猜中一个 Z，所以平均概率≤`尝试次数·1025^2816/(250753^5376)`。示例尝试联合界2²⁰时，log₂ 上界约 **−68239.47**，精确整数检查通过2⁻¹²⁸门槛。这是**平均界和条件式有限证书**，不是每个公开输出的点态后验界，也没有证明真实 SHAKE/计时/失败编程视图都满足该模拟条件。

本轮闭合了对应的整数代数和有限计数，不把原文模拟器与分叉事件本身的前提悄悄删去，也不把20位示例查询预算当作软件强制限制。

## 5. 成本结果及解释

固定工具：[Lattice Estimator `53da598`](https://github.com/malb/lattice-estimator/tree/53da5982597709ba0fdf94ea37a84d822310fd84)，[SIS 源码](https://github.com/malb/lattice-estimator/blob/53da5982597709ba0fdf94ea37a84d822310fd84/estimator/sis_lattice.py)。模型为 ADPS16/Core-SVP，经典0.292、量子0.265，LGSA，无穷范数。同一输入另扫描 β∈{40,80,160,320,480,600,640,672,674,688,736,800}、ζ∈{0,1,128,256,512,1024}，两模型共144点。

四个完整优化输入均给出：

| 输入 | 经典 log₂ 成本 | 量子 log₂ 成本 | BKZ β |
|---|---:|---:|---:|
| 已签身份精确界 | 196.808 | 178.610 | 674 |
| 已签身份保守界 | 196.808 | 178.610 | 674 |
| 新身份扩展矩阵 | 196.808 | 178.610 | 674 |
| 两分支共同放松输入 | 196.808 | 178.610 | 674 |

144点中没有更低结果、没有工具异常；固定扫描是优化器稳健性对照，不是穷尽所有 β/ζ 或证明最优。工具提示其内部欧氏基线忽略形状参数，已记录；最终估计仍是无穷范数。没有把 √m·B 替换成另一个问题，也没有修改外部工具源码。

这是**无结构系数维数的齐次 SIS 对照模型**，不覆盖模格代数/相关结构攻击，也不将核向量求解等同完整 IBS 伪造。复用 M2-B1 的 MLWE 对照时逐项核对实际数学参数和原始文件指纹，没有重算或篡改旧数据；其最低经典/量子区分/部分猜测成本仍为196.199/178.614，秘密搜索约200.467/182.003。

当前稀疏挑战空间267.5669 bit，泛型量子挑战搜索指数133.7835。κ=49 对照只有225.3450 bit，对应112.6725，未达到本轮128搜索指数线；因此保留 κ=64。**上述不同问题的成本不能相加，也不能直接取最小后宣称整体 IBS 为133.78位安全。** 原文分叉优势损失和具体 QROM 模型不是一个“工作量减掉几位”的简单转换。

## 6. 有限预算仍须如实说明

当前 Extract/Sign 最多1024次。掩码立方体的理想新哈希规划中，Extract 约15.542次，1024次中止尾约2⁻⁹⁸·²⁵；独立于哈希的中央区域充分界更松，其得到的中止上界约2⁻⁶·¹²。这**不是观测到约1.4%的失败率**，只是弱充分界，不足以当作完整可用性证书。

Sign 的 z 拒绝部分另记录；r₀、Hint、均匀整数预算、XOF及编程碰撞/生命周期查询预算尚未由这份掩码计算统一给出全界。预算耗尽仍明确报错、不输出默认签名。本轮未调整预算，没有靠功能样本或一个松界宣布其绝对成功/失败；整体 formal release 标记保持 false。

## 7. 测试、复现与文件边界

Windows Python3.14.6/pytest9.1.1；WSL 指定环境 Python3.13.14/Sage10.9；Intel Core Ultra9 275HX，JSON 自动采集环境。本轮不调用 Setup/Extract/Sign，不生成实际用户秘密、身份、消息或密文，不开展硬件密码性能测试；消息/身份长度不适用。算术向量使用显式固定测试带，成本全部是模型数值。

新增 **20 项检查**在 Windows/WSL 通过，相关模块批次为107项；Sage 独立检查2444个任意 Hint 输入、1025个高位升举、12对真实 N/q 的有符号误差多项式、496个小空间非零乘积及2个规范化示例，并保留已签分支零见证反例。最初一项测试/审计预期常数抄为−62719，核验发现实际是−62464，已改为公式计算；既有签名算法没有因此变化，最终失败为0。

当前 Windows 基础选择实跑 **484 passed、2 xfailed**；两个XFAIL仍是旧教育认证反例。完整Sage审计重复生成的结果对象一致，包括成本字段、算术证据、环境和源指纹。没有修改生产代码，因此未手动重复上一轮的全部HIBE/CLI重计算；远端仍按两个独立任务分别检查基础及真实组合，实际状态另行核对。

```text
python -B -m pytest -p no:cacheprovider -q --tb=short tests/test_luo_module_security_screen.py tests/test_luo_joint_parameters.py tests/test_luo_module_math.py tests/test_luo_module_backend.py --junitxml=test-results/module-admission.xml
python -B -m pytest -p no:cacheprovider -q --tb=short tests/test_encoding.py tests/test_lattice_core.py tests/test_prepared_hashing.py tests/test_known_security_gaps.py tests/test_luo_matrix_reference.py tests/test_luo_ibs_contract.py tests/test_luo_parameter_screen.py tests/test_luo_joint_parameters.py tests/test_luo_module_math.py tests/test_luo_module_backend.py tests/test_luo_module_security_screen.py tests/test_byteauth.py --junitxml=test-results/module-admission-basic.xml
wsl --cd /mnt/d/zcode_projects/ibme bash -lc '~/miniconda3/envs/sage/bin/python -B -m pytest -p no:cacheprovider -q --tb=short tests/test_luo_module_security_screen.py tests/test_luo_joint_parameters.py tests/test_luo_module_math.py tests/test_luo_module_backend.py'
wsl --cd /mnt/d/zcode_projects/ibme bash -lc 'PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -B -m experiments.research.luo_module_security_screen --estimator-path "$IBME_ESTIMATOR_DIR" --output docs/research/2026-10-09-admission/module-security.json'
```

`IBME_ESTIMATOR_DIR` 指向仓库外固定、干净的工具检出目录；脚本验证提交和导入位置，拒绝错误版本。Sage 始终使用 `~/miniconda3/envs/sage`。JSON 含原论文、源文件、上一轮结果的 SHA256，无实际私有材料。

## 8. 本轮决策及下一步

当前精确模格输入在这套模型下通过研究成本筛查，保留现有方案/参数，不继续无目的扩大 q，不回退 κ=49；**可以开始规范签名压缩和资源实测**。理论依据继续采用原文经典 ROM 草图加本轮明确的条件映射，完整 QROM/Lean 不是默认下一项。

主 AI 下一轮：保持全部哈希输入及数学签名值不变，做独立版本的规范字节压缩及新/旧格式差分，记录原语和完整密文尺寸变化，再给出后续公平计时边界。压缩是工程格式优化，不另计算法或困难假设。完整密文目前主要由约2.45 MB教学 HIBE 胶囊占据，子环节降幅不能当作全系统加速或原创 A+B<C。

队友继续 CHKP/采样，交接需求仍为固定编码身份86 B、至少32 B种子及参数/资源对应；当前真实组合中 HIBE 仍教学。安全默认入口、全系统侧信道/可用性、完整模型条件和正式组件准入仍 WIP，全部 none/false；已有已修复字节目标和旧教育反例不改变。

新增：`experiments/research/luo_module_security_screen.py`、`tests/test_luo_module_security_screen.py`、本目录 README/JSON。修改：规范、基础 CI 选择、根 README、PROJECT_RESTART、KNOWN_SECURITY_GAPS、主 AI 工作计划。跨研究/规范/CI 是为冻结同一计算口径；没有修改任何原语、协议、CLI、参数 preset 或队友源文件。
