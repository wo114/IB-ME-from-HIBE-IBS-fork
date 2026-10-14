# A2 第二批：原文 AP09 根、位加解密与同组执行域

日期 2026-10-12；继承 A2 原语提交 `9e4b592`，无冲突同步已接收主线 `14f1163`，本批基点 `facbc8d`。**WIP：本批补齐真实 Setup 原语族与位加解密，尚未完成两层 ABB HIBE。** 不重新编写队友已经交付的 CHKP；最新 [PR #14](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/14) 固定头 `87deec2` 在核对时为 OPEN，尚未进入本分支。原版 CHKP 与已合并 MP12 变体仍分别命名、分别引用实测。

## 原文、代码与条件

| 原文 / 要求 | 本批实际行为 | 尚未完成 |
|---|---|---|
| ABB10 §4.1 Setup / Theorem 1；AP09 Algorithm 1、§3.3 | `abb_trapgen` 真实均匀 A1、原文两 bit 之差的 ternary R、Hadamard/digit/U/P 块和整数完整基；不是 MP12 根 | 原文渐近常数、目标困难性与全链选参 |
| AP09 Lemma 3.5、§3.3.2 | 预先固定 `4*d*m2 <= Cprime²*w` 的确定性充分质量门；公开 GS² 界、LHL 距离及 rank/熵中止分列 | 不能把低维非平凡距离界称为安全等级 |
| ABB10 PDF12 Encrypt | 每比特新均匀 s，m+1 个实际 round(连续 Gaussian) 噪声，c0=u0ᵀs+x+b floor(q/2)，c1=Fᵀs+y | 身份 SampleR、两次真实 BasisDel 和字节/Hybrid 完整适配 |
| ABB10 PDF12 Decrypt | 每次真正有限 GPV SamplePre(F,T,u0,τ)，方程检查后使用原文严格整数阈值；准备算术可复用，原像不缓存 | 两层密钥、五类公开对象 codec、固定发钥/失败状态、BackendSpec |
| ABB10 §4.2 条件 | 同组 root/R/sigma1/sigma2/tau/噪声/256 bit/生命周期和资源预检，不拼接不同输入的通过项 | Theorem 3 隐藏 omega 常数、矩阵 RO 和全模型映射 |

核对 [ABB18页作者稿](../../../../papers/2010_lattice_basis_delegation_agrawal.pdf) PDF6–7/9–13及 [AP09完整作者稿](../../../../papers/2009_generating_shorter_bases_alwen_peikert_full.pdf) PDF9/13–17；ABB 的 BasisDel/Encrypt/参数页渲染核对，源码和论文 SHA 见 [审计](audit.json)。本批 API 不改公共 HIBE 接口，也不注册尚未存在的完整 ABB 后端。

新 AP09 执行域为完整维度≤1536、n≤64、奇素数 q<2^256，先核输入/素性/块尺寸/公开质量与整次随机带。它使用原文构造的整数基，独立 `KernelBasis` 再验完整核格、模方程和行列式 q^n。原 `AP09Parameters`/ToBasis192、GPV256、SampleR q≤2^61−1及旧 scalar2^80护栏保持。新 AP09 执行域不代表其余工具已经扩容。

位噪声只复用既有 certified signed scalar：其分布由 **q*alpha** 决定，构建参数显式采用 anchor65537与同一精确 scaled width；实际密文从未使用 anchor 的模投影，证书另列真实 q/alpha。测试验证这一映射，不复制另一个噪声算法。生产默认 SecureRandom，固定熵只用于明确测试。

## 实际执行与失败历史

新单元测试实际生成 208 维 AP09 根并核完整格；它是单元 witness，不混入下面248维实验。原位加解密夹具是**公开 gadget 基**，也不混称为真实 Setup 结果。

真实 root-bit 输入：`n=1,q=549755813911,d=m1=56,m2=192,m=248,Cprime=32`，公开根 GS²充分界68605，ε_bits128，实际根后独立均匀 u0；8个比特，每比特新 s 与噪声，q*alpha=4。位加密 tail128/mass192/precision256；GPV使用原 FirstFiniteOptions（tail128/mass256/precision320/abort128），τ²=4*68605*137=37595540。身份不适用：本批只试真实根下的原文一比特算法，没有调用身份哈希或委派。

首次实际生成根、执行八比特并保存根/密文后，最后读取 Git 提交时因 WSL 不识别 Windows managed-worktree gitdir 失败。原始私有目录与 completed 标记保留，**没有可发表的原始耗时和熵计数，记为 null**。不能由后来测量倒填该历史。现在探针在熵前要求宿主核对的提交 SHA，并逐阶段保存记录，记录异常不再丢失数学阶段。

随后只读加载同一份完整根/八个密文，重新执行原文允许的八次独立 SamplePre 解密： [收据](root-bit-restoration.json) 10阶段通过、**新根0/新加密0**，保存的八比特全部匹配。该次新进程约86.108秒，其中GPV/噪声准备84.564秒，恢复0.100秒，八次解密各0.151–0.250秒；消耗842667系统随机字节，进程峰值RSS257988 KiB。不是新生成实验、完整HIBE或公平性能排名。

公开收据去掉了两项依赖私有基几何的 scalar-TV/tape诊断；原私有收据保持，算法 provider 源哈希与最终代码相同。收据中的 runner SHA 属于当时执行版本，审计明确记录发表层的两字段删除，不把发表层修改称为重跑。没有公开私钥、实际密文、u0/根矩阵、原像或私人几何。

环境实际核对：Intel Core Ultra9 275HX，WSL可见 MemTotal16092856 KiB，Linux6.18.33.2-microsoft-standard-WSL2，Sage10.9/Python3.13.14，Windows Python版本见审计；共享开发机、一次固定批次，不求稳定均值。

**同一份八个实际密文也被公开 n=1 枚举攻击唯一恢复。** [攻击收据](public-attack.json)对每个密文枚举93个公开有限噪声候选，攻击函数只接收公钥、密文和公开半径，不接收基/原像/RNG；全部唯一候选与实际比特相同。加载器从保留探针文件投影公开字段，此文件本身还含私有基，不能称加载器只打开了公开文件。该负控证明当前输入不具备保密强度，不能推荐或部署。

## 同一完整配置的筛查

[参数/资源投影](parameter-screen.json)均为估算、无熵、未生成较大 key。R 的谱范数用**实际有限支持的 Frobenius 上界**控制；sigma1/sigma2 用共同 C1 充分因子，父/叶质量按 RandBasis 成功范数事件算，再给τ/解密误差。它是公开保守充分链，不是对 ABB 隐藏常数的实例化，也不是必要条件。

| 同组输入 | 原文保守维度门 / 根距离 | 条件噪声界 | 现有工具第一缺口 |
|---|---|---|---|
| n1/q≈2^39/m248 | 维度门通过；根距离界非平凡但很弱 | 两次委派后的保守界失败；上面的根位算法成功不能传给两层 | ToBasis/BasisDel192维，叶scalar2^80域 |
| n1/q=2^61−1/m800 | 维度门通过；根距离界<2^-64 | 保守界失败 | 192/256维及叶scalar域 |
| n1/q>2^159/m1280 | 维度门通过；根距离界<2^-64 | 条件式理想噪声寿命界2^-100，32B/256比特及2^20次，**不是安全位数** | 192/256维、SampleR模数、叶scalar域均不支持 |
| n2/128/256，160bit q | 保守维度最低1921/122881/245761；完整基entry数和假设256bit槽成本另列 | 未计算，不能记pass/fail | 新AP091536维域也不支持 |

表中根距离、范数坏事件、DGS/噪声有限实现误差、中止和存储风险分别处理；噪声寿命界只在所用预像范数事件成立时有效。假设256bit系数槽的尺寸是估算，不是尚未实现的 codec 实测。n1 无困难性，所有 profile 都保持 none/false；此筛查不把正式参数门降低，也不为大采样删 guard。

下一步 A3 为真实消费者扩展共享精确委派/GPV/宽 Gaussian 域，并先做无熵资源核验；A2再接两次BasisDel、对象/状态及真实Luo组合。CHKP已交付研究链无需重写；正式尺寸/困难性与全模型对应仍待统筹和owner共同核验。AR储备不是本批完整编码。

## 测试和重放

最终 Sage 范围 **116 passed / 3 skipped**，含本批33项新测试；三个旧私有 native/84维 witness 本新工作树没有，skip不算pass。Windows **116 passed / 5 Sage依赖skip**。两批含共同测试，不能相加成独立场景数。[Sage JUnit](sage.junit.xml)、[Windows JUnit](windows.junit.xml)与准确命令/失败修正见审计。没有调用全组合测试、没有 wheel 安装验证、没有ABB公开六方法验收。

从源码根运行，先由宿主 `git rev-parse HEAD`取得SHA再传给Sage；WSL统一采用 `~/miniconda3/envs/sage`：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.abb_rom.root_bits_probe \
  --private-directory test-results/abb-fresh/private --output test-results/abb-fresh/receipt.json \
  --baseline-commit <宿主核对的40位提交SHA>

PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.abb_rom.parameter_probe \
  --output test-results/abb-fresh/parameter-screen.json

PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.abb_rom.public_attack_probe \
  --saved-private-directory test-results/abb-fresh/private --output test-results/abb-fresh/public-attack.json
```

若已成功完成数学阶段但发表元数据失败，可传 `--saved-private-directory <原完整private>`并选择新private/输出路径执行保留实例核验；不删除原目录、不重新发根、不把新解密计作旧原像复用。算法/采样失败不由该恢复入口重试。当前loader是探针受控私有产物加载，不冒称对外严格五类codec。

本批提交信息：`feat(hibe): add original ABB TrapGen bit encryption and same-input screen`。修改清单：

- A源：`src/ibme/hibe/abb_rom/{__init__,trapgen,bit_encryption,parameter_screen}.py`。
- A探针：`experiments/research/abb_rom/{__init__,root_bits_probe,parameter_probe,public_attack_probe}.py`；`experiments/attacks/abb_small_dimension.py`。
- 专属测试：`tests/test_abb_rom_trapgen_and_bits.py`、`tests/test_abb_rom_parameter_screen.py`。
- 本目录 README、audit、参数/恢复/公开攻击收据与两个JUnit。
- 仅更新共享进度/登记的A2对应描述，理由是旧“无TrapGen/位加解密”与实物已经冲突；不改变协议、registry、CLI、B/C文件或根规范。

测试通过不代替LWE、委派、矩阵RO或Wang组合安全证明。`security_claim=none / backend_admitted=false / parameters_are_formal=false`；A目标仍进行中，后端/正式模型和参数/AR等未实现内容不得由本批partial交付充数。
