# A0：矩阵 HIBE 的同组高维条件、攻击角色与资源筛查

本批承接[成员 A 任务书](../../../workplans/2026-10-12/A-矩阵HIBE任务.md)的 A0，代码冻结为 `399633a`。此前的 [ABB 完整生命周期、2×2 多地址和 Luo 组合验收](../2026-10-14-abb-complete/README.md)已经完成，沿用其原始收据；本批没有重采样小维根或私钥。

**实际完成：三条明确命名的矩阵 HIBE 路线、30 个高维参数投影、36 个 LWE 角色、144 次攻击模型调用。没有选出满足现有执行条件的下一组参数。** 这是对这些完整投影的结果，不是其它参数、算法或压缩表示都不可能的结论。A 的研究功能实物已交，G-formal 和可部署高维后端仍为 WIP。

## 1. 同一组输入及算法边界

入口：[scaled_parameter_screen.py](../../../../experiments/research/abb_rom/scaled_parameter_screen.py)。它只构造公开整数条件和既有标量 Gaussian 证书，不构造高维矩阵，不实例化越界的后端 Params，也不生成根、私钥、噪声样本或身份随机预言机输出。禁止随机源/采样器调用的测试已实际通过。

- n 为 128、512、2048、4096、8192、16384；61 位素数 `2305843009213693951` 用于三条路线，104 位 `10141204801825835211973625643089` 和 160 位 `730750818665451459101842416358141509827966271787` 另用于 ABB。
- 内层输入为两层各 86 B 身份、32 B seed、256 位、2²⁰ 次封装；epsilon128、条件噪声 error128。每个投影算一次，没有性能重复样本或成功率统计。
- root R / SampleR 的有限标量证书采用 tail128、mass256、precision320。投影中的连续加密噪声仅做理论条件检查，**没有构建其有限噪声表或合并全部分布误差**。
- 取最小整数 χ，使 χ²>4n，令 α=χ/q。这是本批的筛查族，并非最优噪声选择；MP12 计算型分支同时取根 R 的平方宽度 χ²。根宽度与密文噪声未分别优化。
- [ABB 原稿](https://crypto.stanford.edu/~dabo/pubs/papers/latticehibe.pdf) Definition 6 / Theorem 2 / §4.1–4.2 要求舍入连续 Gaussian，并在引用 Regev 归约时满足严格 qα>2√n。单独满足该数值前提不提供困难性等级。平方 n 的等号边界也经过测试；没有沿用现后端只接受 qα=4 的执行配方。

| 投影名称 → 实际后端 | 根 / 父 / 叶 | 本批有限条件及仍未闭合项 |
|---|---|---|
| `mp12-chkp` → `mp12-chkp-reference` | MP12 计算型 `[I\|Â]` 根 / Algorithm 4 DelTrap / CHKP 固定256原像 | m̄=2n；根 Frobenius 界、委派宽度、父完整基界、叶宽度与噪声用同组输入。根 LWE 另算；未启用 Algorithm 3，原 CHKP 定理不直接继承 |
| `chkp-rom` → `chkp` | MP12 统计根转完整基 / CHKP ExtBasis–RandBasis–ToBasis / 最大深度固定256原像 | 根 R²=1024；实际标量质量下界>31.9，精确搜索 m̄ 达理想 LHL 项2⁻¹²⁸。根/父公开 GS 与叶宽度重算；该 LHL 项不包含有限耦合、rank、中止或全部归约损失 |
| `abb-rom` → `abb-rom-finite` | AP09 Algorithm 1/§3.3 / 两次真实 BasisDel 的公开界 / 每位新 SamplePre | d≥2n⌈log₂q⌉并增补 LHL 余量，m=m₁+m₂；Hadamard、严格 Setup 维度、SampleR 实际有限半径、Frobenius 算子界、两层宽度及噪声同算。没有假设高维也能达到 n1 的规范化质量；Theorem 3 隐藏常数、RO/分布映射仍未闭合 |

CHKP 与 ABB 的统计根不被误写成 MP12 计算型根；其 `root_lwe=null` 有明确原因。统计根只解决与均匀的相应比较项，不能免除密文 LWE 困难性、短陷门攻击或模型核验。各 profile 的算术字段、尺寸和执行门在两个完整 JSON 中，不用另一个配置的通过项拼接。

## 2. 攻击输入和模型结果

复用[固定 Lattice Estimator](https://github.com/malb/lattice-estimator/tree/53da5982597709ba0fdf94ea37a84d822310fd84)，执行前后均核 HEAD 与干净工作树。模型为 ADPS16 经典/量子 Core-SVP；primal-uSVP 用 LGSA，plain dual 用该固定版本的实现。没有 BDD/hybrid、BKW 或代数攻击，不声称覆盖所有已知攻击。

1. MP12 计算根逐列暴露 n 维小 Gaussian secret/error LWE，每列 n 个样本、nk 个独立列。估计的是一列的搜索/区分成本；没有乘算多目标、完整替代陷门或归约损失。
2. CHKP 共享前导对一个随机向量有 3m 个公开样本；已知整个 seed 时另有256个样本。本批估计使用公开前导，从而标签对应于先恢复向量再解消息。
3. ABB 每位有新随机向量，只把该位 c1 的 m 个样本交给估计器；已知该位可再加1个。**没有将256个不同随机向量的样本拼为同一个 LWE 实例。** 256目标和逐位适配的安全损失仍须单列。

密文的真实噪声是舍入连续 Gaussian。估计器接收 σ=χ/√(2π) 的离散 Gaussian **比较模型**；根的理想 D_Z,s 及有限实现也保持分开。因此下表不是实际攻击耗时、完整密钥恢复实测或安全位数。

| 同组投影 / 角色 | primal-uSVP log₂(rop)，经典 / 量子 | 条件噪声充分门 | 父完整基编码下界 |
|---|---:|---|---:|
| MP12 n128/q61 根；密文分别计算 | 11.972 / 10.865 | 密文通过 | 1,560,674,304 B |
| CHKP n128/q61 密文 | 11.972 / 10.865 | 通过 | 2,133,292,416 B |
| ABB n128/q160 密文 | 11.972 / 10.865 | 通过 | 161,061,273,600 B |
| MP12 n2048/q61 根 | 103.660 / 94.075 | 密文未通过 | 399,532,621,824 B |
| MP12 n2048/q61 密文 | 102.492 / 93.015 | 未通过 | 同上 |
| MP12 n4096/q61 根 | 269.224 / 244.330 | 密文未通过 | 1,598,130,487,296 B |
| MP12 n4096/q61 密文 | 266.596 / 241.945 | 未通过 | 同上 |
| ABB n4096/q104 密文 | 119.720 / 108.650 | 未通过 | 69,681,549,410,304 B |
| ABB n4096/q160 密文 | 58.984 / 53.530 | 未通过 | 164,926,744,166,400 B |

较大的成本不会覆盖同一行的噪声、维度、尺寸失败；增大 q 在同维度/同 χ 下也会降低部分攻击估计成本。当前30行仅4行通过所选的条件噪声充分门，全部超出现有执行门；未通过充分条件不等同实际解密必然失败。

144次调用准确分为 **98个有限估计、28个无有限估计、18个错误**。高维处固定版本有 `KeyError('beta')`；原始错误逐项保留，不改外部工具、忽略错误后取安全最小值或把空结果填成无穷安全。新增测试显式核无有限结果/错误均保存 null。本批增加 n4096 是为了补 n2048 与 n8192 之间的观察点，原25行未覆盖、替换或重写。

## 3. 资源决定和 A3 后继边界

采用现有整数逐项编码最少6 B、紧凑 JSON 中间 trapdoor 至少4 B，以及模系数的字节对齐下界；这些是**格式下界**，不包含头部、嵌套状态、缓存和工作区。下界超过限额可以拒绝，下界小于限额不能宣称对象适合。RSS、实际高维阶段时间均为 null。

- n128/q61 的 MP12 父基已至少1.56 GB，CHKP至少2.13 GB，超出现有私密组件/GPV/完整基域。只保存 DelTrap 矩形中间 trapdoor 也不能自动消除当前消费者重新展开完整基的成本。
- ABB n128/q160 单基至少150 GiB，32 B胶囊仅系数已838,865,920 B，超出4 MiB胶囊；原始有限宽度链还有叶/解密标量域障碍。不能据 n1 的质量门假设高维也可同样压低宽度。
- n4096/q61 MP12 纵使部分比较成本很大，父基至少1.60 TB、叶胶囊系数6,195,200 B，且本组条件噪声失败；dual 的无有限估计仍未知。当前 n≤64 入口、矩阵1536维或 CHKP512维上限保持原状。

决定：**不为本批30行启动越界根/委派采样，不通过扩大数值 guard 或换小 n 将其升级为安全参数。** A3 下一实物应核验适用于消费者的结构化陷门/采样表示及其公开接口、分布/谱界，先证明无需展开现完整基并量化资源，再投入新的高维实验。MP12 Algorithm 3 属于待核独立实现，不是本批已经接入；ABB 原路径和质量条件化必须保留自身证据。噪声/根宽度分别优化、其它选参族和正式困难性仍待，不能把本次有限筛查当穷尽不可能性证明。

## 4. 复算、测试和证据

在 WSL 的仓库根，`<固定估计器目录>`为干净的上述固定提交；可复用已有本地目录，不把某机器的 WSL home 写入脚本。

```sh
export PYTHONPATH="$PWD/src:$PWD"
export OMP_NUM_THREADS=8 OPENBLAS_NUM_THREADS=1
~/miniconda3/envs/sage/bin/python -u -m experiments.research.abb_rom.scaled_parameter_screen \
  --estimator-path <固定估计器目录> --output test-results/scaled-new.json
~/miniconda3/envs/sage/bin/python -u -m experiments.research.abb_rom.scaled_parameter_screen \
  --dimensions 4096 --estimator-path <固定估计器目录> --output test-results/scaled-n4096-new.json
~/miniconda3/envs/sage/bin/python -m pytest -p no:cacheprovider -q \
  tests/test_matrix_hibe_scaled_screen.py
```

输出文件必须不存在。不给 `--estimator-path` 只生成公开条件，不执行攻击模型；该结果不能冒称估计已运行。当前程序是公开筛查，不是高维运行脚本或安全参数 factory。

| 本批实跑 | 结果 / 收据 |
|---|---|
| 原25行同组筛查 | [完整参数、原始估计/错误与源码散列](evidence/scaled-25.json)、[标准输出](evidence/scaled-25.log) |
| 补5行 n4096 | [完整参数与原始估计](evidence/scaled-n4096.json)、[标准输出](evidence/scaled-n4096.log) |
| 新测试，Sage | **22 passed / 0 skipped**，[JUnit](evidence/final-sage.xml)；严格边界、独立噪声不等式、旧屏同根几何链、角色、零采样和未知状态 |
| 新测试，Windows Python3.14 | **17 passed / 5 skipped**，[JUnit](evidence/final-windows.xml)；5项确需 Sage，不能计为通过 |
| 相关参数/质量/账本最终回归 | **43 passed / 0 skipped**，[JUnit](evidence/final-regression.xml)，30.93秒；设置固定 Flatter/精确 Gram 工具后实际执行全部10项质量门检查，含上述22项新测试，计数不相加 |
| 未配置 native 的先行回归 | **32 passed / 10 skipped**，[原始 JUnit](evidence/related-regression.xml)；新测试当时21项，10项明确因缺显式 native 环境跳过；最终状态见上一行 |
| 首轮开发失败 | [原始 JUnit](evidence/first-attempt.xml)：19 passed/2 failed，为 Sage 有理数转换到 Python Fraction 的接口兼容问题；已在冻结提交修复，最终22项通过。没有丢弃参数失败/攻击错误 |
| 环境、版本、命令、结果散列 | [audit.json](audit.json)；公开运行源码起止散列一致，估计器固定且干净 |

环境：Intel Core Ultra9 275HX、Windows宿主、WSL Linux6.18.33.2、Sage10.9/Python3.13.14；精确 Python/platform 见收据。模型依赖 ROM/工程 SHAKE 的原边界保持；本批没有调用 H/G。投影不属于正式参数，原小维实物仍是不安全研究/教学负控。保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。参数测试、估计成本与功能收据都不能替代 LWE、匿名 HIBE、委派或完整 IBME 安全证明。

本批修改只含 A 专属筛查、新测试和本目录；未改公共 registry、协议、CLI、默认参数、队友后端或任何原始私有状态。
