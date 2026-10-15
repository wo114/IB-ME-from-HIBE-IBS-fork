# A0：同组目标参数、两个LWE角色与明确资源拒绝

本批承接[具体有限账本与现有域排除](../2026-10-15-finite-budget/README.md)。PR33固定head `51e0059`的46项远端检查成功，另2项手动strict-security未执行，已合入 `c82eba7b4244a4719911a85bcb21249faeaf6716`。本地合并树与该head一致。当前继续A，三条储备GKR/ABB标准模型/CHKP标准模型暂缓。

新增实物是完整目标参数筛查器和公开身份前导变换；**没有新增高维HIBE后端或正式安全参数**。四组投影的根、父、叶、噪声和资源全部取同一组输入，分别估算根与密文的LWE角色。现有后端、协议、wire和资源门不变。

结论：新分析配方可使资源条件成立时的累计概率上界≤`2^-131`；四组中n4096的已测Gaussian比较模型成本较高，但现有单父R的JSON表示至少209,278,992,384 B，且77位q不能放入现行uint64头。**拒绝把该投影当作当前可运行或已安全准入的配置。** A0得到明确的目标输入与第一阻塞，A整体仍为WIP。

## 1. 公钥单位阵与两个独立角色

来源为[MP12固定作者稿](../../../../papers/2011_lattice_trapdoors_micciancio.pdf) §5.2“Computational instantiation”（PDF25）、§5.4/5.5，以及CHKP固定作者稿§5的完整H/G。MP12 PDF SHA256保持 `bf1160f088825ed28c343b299f5bc2acdca41cc50293310a03a4506d2fdbdb84`。

计算型根为 `Abar=[I|Ahat]`、`A0=[Abar|G−Abar R]`。将 `R=[R1;R2]` 分成两个n行块，公开根列给出普通normal-form关系 `Ahat R2+R1`（已知G和符号可消去）。根角色按**一列**n个小Gaussian秘密、n个小Gaussian误差和n个样本估算；w列共用Ahat且各有新秘密。列数/混合损失和完整陷门恢复不由单列成本替代。

密文前导为 `c=A_leaf^T s+e`。首n列确为I，故 `c_I=s+e_I modq`。只取两块完整身份矩阵 `H=[H(rcv)|H(rcv,phi)]`，公开可计算

```text
b_H = c_H − H^T c_I = H^T (−e_I) + e_H mod q.
```

因此这个密文视角的秘密是**负的前n个rounded-noise**，误差是H块各坐标的rounded-noise，样本数为完整的 `2m`。均匀s使c_I与e_I独立；两块H在声明的ROM模型内独立于噪声。该视角无需把根的其它列当作独立均匀矩阵，也未使用256个terminal提供的额外约束。源代码 `structured_identity_view.identity_noise_view` 检查真实首I、完整3m布局、公钥延伸和规范模数值。

这是标准normal form；固定版本Estimator自己也支持这种转换。新增工作是把当前后端的具体公开布局、分布和可用样本来源明确映射，**不宣称新的攻击原理**。密文的字面分布是有限rounded-continuous Gaussian；本批Estimator使用同宽度DiscreteGaussian比较模型，尚无把这些成本直接转成字面实现安全位数的结论。

## 2. 同一目标组的选择与累计配方

`structured_target_screen.py`只生成公开数值、k维gadget基、有限标量类和整数噪声CDF，不生成大矩阵、R、Schur逆、密钥或Gaussian样本。候选n为128、512、2048、4096。每行固定：

```text
k=ceil(log2 q), w=nk, m=n(k+2)
root_R_squared=4n+1, B0=2nw·root_R_squared
r²=4·K(w,192), K(d,b)=ceil(log2(2d(1+2^b)))
s_parent²=max(7r²(1+B0),10r²(w+B0))
D_parent=w+4n, B1=D_parent·w·s_parent²
s_leaf²=max(7r²(1+B1),10r²(w+B1)), D_leaf=3m
qα=floor(2sqrt(n))+1.
```

根R平方宽与密文qα分别超过相应 `2sqrt(n)` 的数值前提；这只是必要条件，不是全部归约映射。两个H块始终各n×m，seed32 B/256位，身份限额86 B、2接收者×2发送者。

逐位数区间先推上述全部宽度，再用现行decoder的精确整数phase半径 `(q//2−1)//2` 与连续/舍入项求最小可行phase和该配方的最小素数q。素性用Sage证明；前一个素数作为边界反查。每行使用该同组q，没有把小q困难性与大q正确性拼接。

以下是**未登记、未实现为HIBE profile**的192位分析配方：scalar tail/abort192、mass320、precision384、scalar及根均匀拒绝帽256，gadget epsilon192，扰动512次，rounded-noise tail192，单bit解码界160，密文secret/理想RO拒绝帽192。保留完整树和 `2^20` 次封装、各 `2^20` 个H地址/G路径预算。每行的累计模型上界都落在 `(2^-132,2^-131]`，达到声明的 `2^-128` 概率目标；当前实际v1仍沿用旧配方，原 `2^-97` 结论不被改写。

计算复用实际有限标量、k维GPV和CDF区间函数。整数噪声CDF只依赖 `χ=qα`，在half-integer边界实际构造320-bit阈值；之后modq是确定后处理，因此无须借用另一个q来拼接噪声证书。投影中巨大的范数指数向上保守截到256，以避免分配十亿位整数。误差项含有限proposal、Bernoulli、gadget、扰动中止、根/父/叶范数、噪声、均匀secret及理想RO拒绝。私有精确算术路径、整调用随机带及机器资源没有被准入。

## 3. 实际32次攻击模型估算

使用干净固定 [Lattice Estimator](https://github.com/malb/lattice-estimator/tree/53da5982597709ba0fdf94ea37a84d822310fd84)，commit `53da5982597709ba0fdf94ea37a84d822310fd84`，ADPS16 classical/quantum Core-SVP，primal-uSVP LGSA与plain dual。四组×两角色×两模式×两算法共32次，全部返回有限估算；没有把error或unknown填成高成本。

| 同组n | 同组q位数 | 根角色已测量子成本最小log₂(rop) | 密文角色已测量子成本最小log₂(rop) | 累计模型概率上界≤ |
|---:|---:|---:|---:|---:|
| 128 | 59 | 10.601 | 10.601 | 2^-131 |
| 512 | 67 | 10.601 | 10.601 | 2^-131 |
| 2048 | 74 | 68.635 | 68.105 | 2^-131 |
| 4096 | 77 | 171.190 | 170.130 | 2^-131 |

n4096这一行q=`149785881362170169333047`、根R平方宽16385、qα129。primal-uSVP经典根/密文成本指数188.632/187.464。两角色保持分列，既不把概率131当作困难性，也不把Gaussian比较模型的170授予实际HIBE或IBME。BDD/hybrid、BKW、代数及多目标、ROM/256-bit归约损失尚未全部计入；密文额外公开列和terminal未用于这些模型，完整安全准入仍不成立。

## 4. 资源下界与执行决定

| 同组n/q位数 | 父R整数个数 | 单父R JSON最低B | 单叶256原像wire最低B | 公共seed capsule系数最低B |
|---:|---:|---:|---:|---:|
| 128 / 59 | 60,899,328 | 121,798,656 | 35,979,264 | 189,440 |
| 512 / 67 | 1,247,019,008 | 2,494,038,016 | 162,791,424 | 956,160 |
| 2048 / 74 | 24,209,522,688 | 48,419,045,376 | 717,225,984 | 4,672,000 |
| 4096 / 77 | 104,639,496,192 | 209,278,992,384 | 1,491,075,072 | 9,710,080 |

父R尺寸是 `(w+4n)×w`。设p行共E项，当前规范JSON即使全为一位非负数字，也需至少 `2E+2p+1` B，因此采用 `2E` 是保守下界；公钥、符号和真实位数只会继续增加。当前每个signed叶整数至少1 B符号、4 B长度、1 B幅度，即至少6 B/项。上述是现有逐项表示的**存储/传输下界**，不是峰值RSS或采样耗时估计。

n4096仅父R最低约194.906 GiB，已超过32 MiB对象门；完整叶约1.389 GiB，超过16 MiB固定状态门。公钥root residues最低13,254,000,640 B，超过2 MiB公开oracle字段门；capsule系数最低约9.260 MiB，超过2 MiB raw和4 MiB Hybrid门。其叶采样器按当前实现会需要655360维Schur逆，即429,496,729,600项，实际没有构造。n512起的q也越过现有uint64头，不能只增加一个n上限。

当前版本按既有G-run门拒绝所有四组。正式运行需要解决实际委派表示/算术、资源、wire版本和完整参数准入；本批没有放宽门或发起这些巨大根/发钥。下一次大采样前应先拿到一个通过这些输入/资源条件且完成困难性与构造条件核验的同组候选。A1/A2已有实物可继续做无此依赖的条件核验，不以独立新根补位。

## 5. 公开原实例验证、测试与复放

从上批真实n2系统实例只读 `public.bin` 和 `ciphertext-0-0.bin`，按H-only normal form枚举8649个有限误差元组，保留1个secret候选并恢复原32 B消息。只发布恢复摘要；真实secret、误差、R和私钥不输出。没有读取master/parent/leaf或随机带，也没有新根、新发钥、采样和熵请求。实际公开布局与比较模型映射得到验证；这仍是原n2负控，未重复计成新HIBE或新安全实例。

数学/模型执行源 `9a9dedcea1b7506f43172424bc447869692f0472`（`feat(research): screen complete structured targets and public LWE normal form`）；安装probe为后续 `0172694`，包内数学源相同。最终Sage严格专项 **125 passed / 0 skip**，Windows纯代数/域检查 **19 passed / 0 skip**，集合有交叠，不相加。专项另实际执行了一个71位素数的公开k维gadget Gaussian TEST采样，验证完整格和余类方程；它不新增HIBE根或后端。

wheel SHA256 `f585fd37c698e51bb81377b3338488a87ab48a11ae008a3172af30e6d1289a27`，1,394,335 B。仓库外cwd、`python -I` 和唯一安装provider根下，全部4组公开投影及同一原n2公开攻击复放通过，48个项目provider来自安装目录。四组全部参数、分布、资源与模型定义均与源码相同；安装轮没有重新运行32次Estimator。投影和公开攻击均无新根/发钥/采样/项目熵请求，不把此复放当成高维后端生命周期。

初次6项目标测试有1项因Sage `previous_prime`不接受 `proof=`关键字而失败；随后用正确API并显式证明返回素性，同一最小素数/decoder边界判据通过。原始失败JUnit保留，未降低判据。最终对目标与公开视角的定向13项全部通过后，执行125项完整专项。

在仓库根和指定WSL环境，用新输出路径运行：

```sh
mkdir -p test-results
export PYTHONPATH="$PWD/src:$PWD"
export OMP_NUM_THREADS=4 OPENBLAS_NUM_THREADS=1
~/miniconda3/envs/sage/bin/python -m experiments.research.structured_target_screen \
  --dimensions 128 512 2048 4096 --estimator-path <干净固定版本的Estimator目录> \
  --output test-results/my-target-groups.json
~/miniconda3/envs/sage/bin/python ci/run.py run a-structured-hg --output test-results/my-a-target-check
```

Estimator路径是显式工具输入；没有把本机WSL用户目录写进脚本。Sage使用 `~/miniconda3/envs/sage`。硬件/软件、公开证据摘要、安装复放和精确改动列表随本批audit记录；私有原始状态留在ignored目录。

**A仍未全部完成：**正式困难参数与可运行完整域、安全定理/模型/固定服务对应、现有后端实际采用并验收新的累计误差配方、相同安全目标的完整IBME基线/消融仍待。保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。本批零项完整安全证明；数学方程、模型估算和测试不替代安全证明。
