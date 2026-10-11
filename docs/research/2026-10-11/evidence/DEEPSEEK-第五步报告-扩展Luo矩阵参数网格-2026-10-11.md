# DeepSeek 第五步报告：扩展 Luo 矩阵参数网格与候选生成

日期：2026-10-11｜仓库外驱动脚本（未修改仓库任何文件）；实跑 10 行扩展网格 + 2 项公开伪造负对照。

## 1. 固定筛选口径和环境

- **论文算法版本**：Luo–Chen–Susilo–Huang，ICICS 2024，§3 Algorithms 1–4 + Theorem 1（经典 ROM、自适应 EUF-ID-CMA、SIS_{n,m,q,d}，d=2γ2+2κβ1，分叉损失 ≈δ²/(s+h)²）。参数字段：n（SIS 行数）、m（矩阵列数）、k（挑战向量维数）、q（奇素数模数）、η（主秘密系数上界，固定 1）、κ（挑战 ±1 个数）、γ1/γ2（Extract/Sign 掩码界）、β1=κ·η、β2=κ·γ1。
- **约束**（`_validate`）：m>n；κ≤k；q 奇；γ1>κ·η；γ2>κ·γ1。
- **三层筛选含义**：公开恢复筛查=小参数指数枚举（`recover_small_master`）；master-LWE 公开变换=A0 可逆时 A0⁻¹T=S0+(A0⁻¹A1)S1 的单列 LWE 实例（区分/搜索成本分标，**不是完整伪造归约**）；SIS 估计=对 Theorem 1 范数界的格攻击启发式成本。
- **estimator**：commit `53da5982597709ba0fdf94ea37a84d822310fd84`（WSL `~/lattice-estimator`，clean_checkout=true）；成本模型 ADPS16（经典 0.292/量子 0.265，Core-SVP 启发式）+ lgsa 形状模型；SIS 用 infinity 范数。
- **环境**：WSL Ubuntu-24.04，Sage 10.9 / Python 3.13.15；驱动脚本 `/mnt/c/Users/A/AppData/Local/Temp/luo_grid_ext.py`（复用 `luo_parameter_screen.py` 的 `planned_large_row/screen_row/master_recovery_lwe_input/lwe_attack_goal/public_forgery_controls`，不修改仓库）。
- **筛选阈值 ≠ 安全等级**：challenge_bits≥128、sis_bound<q、master-LWE/SIS 估计值都只是筛查阈值；任何 rop_log2 不构成安全位数声明。

## 2. 扩展网格生成规则（10 行，有界）

1. m/n ∈ {4, 8}——抬升 master-LWE 单列实例的样本/维数比（m/n=4 时秘密维 3n、样本 n；m/n=8 时秘密维 7n、样本 n）；
2. k/κ ∈ {(128,32), (192,48), (256,64), (256,32), (192,16)}——观察挑战空间（comb(k,κ)·2^κ）与签名尺寸；含一行 κ=16 的边界行（challenge_bits=92<128）；
3. q = next_prime(2^61)、next_prime(2^77)、next_prime(2^91)——奇数素数，逐行 is_prime 核验；
4. γ1/γ2 沿用 planned_large_row 的 ~10 次试验规划（γ1≈m·k·κ/ln10，γ2≈m·κ·γ1/ln10），β1=κ·η、β2=κ·γ1，SIS 界 d=2γ2+2κβ1；
5. 固定 10 行，禁止无界搜索；每行记录全部字段（参数/约束/素性/挑战空间/尺寸/估计/错误）。

## 3. 全部候选筛查表（10 行实跑，elapsed 1239.7s）

| 候选 | 参数（n/m/k/κ/q） | 代数约束 | 公开恢复 | SIS lattice（经典/量子） | master-LWE 公开变换（经典/量子） | 原始尺寸（pk / 签名） | 结论 |
|---|---|---|---|---|---|---|---|
| g4-n128-k128-c32-q61 | 128/512/128/32/2⁶¹⁺ | 通过 | 不适用（大参数） | **工具失败**（estimator TypeError） | dual 2^11.68 / 2^10.60；usvp 2^11.97 / 2^10.87 | 640 KB / 133 KB | 排除（LWE 坍塌） |
| g8-n128-k128-c32-q61 | 128/1024/128/32/2⁶¹⁺ | 通过 | 不适用 | 工具失败 | dual 无；**usvp 2^75.63 / 2^68.64** | 1.13 MB / 137 KB | 待补 SIS 估计 |
| g4-n256-k192-c48-q61 | 256/1024/192/48/2⁶¹⁺ | 通过 | 不适用 | 工具失败 | dual 2^25.99 / 2^23.62；usvp 2^24.82 / 2^22.53 | 2.38 MB / 394 KB | 排除（LWE 低） |
| g8-n256-k192-c48-q61 | 256/2048/192/48/2⁶¹⁺ | 通过 | 不适用 | 工具失败 | dual 无；**usvp 2^185.13 / 2^168.01** | 4.38 MB / 402 KB | 待补 SIS 估计 |
| g4-n512-k256-c64-q61 | 512/2048/256/64/2⁶¹⁺ | 通过 | 不适用 | **2^19.86 / 2^18.02** | dual 2^79.13 / 2^71.82；usvp 2^77.38 / 2^70.23 | 9.00 MB / 1.02 MB | 排除（SIS 低） |
| g4-n512-k256-c64-q77 | 512/2048/256/64/2⁷⁷⁺ | 通过 | 不适用 | **2^33.00 / 2^29.95** | dual 2^56.06 / 2^50.88 | 11.3 MB / 1.27 MB | 排除（两侧均低） |
| g4-n512-k256-c32-q77 | 512/2048/256/32/2⁷⁷⁺ | 通过 | 不适用 | **2^39.13 / 2^35.51** | dual 2^56.06 / 2^50.88 | 11.3 MB / 1.27 MB | 排除（SIS 低） |
| g8-n512-k256-c64-q77 | 512/4096/256/64/2⁷⁷⁺ | 通过 | 不适用 | **2^26.57 / 2^24.12** | dual 无；**usvp 2^334.63 / 2^303.69** | 21.3 MB / 1.29 MB | 候选（SIS 待修） |
| g8-n512-k256-c64-q91 | 512/4096/256/64/2⁹¹⁺ | 通过 | 不适用 | **2^37.08 / 2^33.66** | dual 无；**usvp 2^278.57 / 2^252.81** | 25.5 MB / 1.54 MB | 候选（SIS 待修） |
| g4-n256-k192-c16-q61 | 256/1024/192/16/2⁶¹⁺ | 通过 | 不适用 | 工具失败 | dual 2^25.99 / 2^23.62 | 2.38 MB / 394 KB | 排除（challenge_bits=92<128 + LWE 低） |

**统计**：运行 10 行；0 行通过全部筛选层；5 行 SIS 工具失败（n=128/256）；5 行数值完整（n=512）；**当前网格仍无合法候选**。

## 4. estimator 运行结果和失败项

- **失败项**：5 行（全部 n=128 与 n=256 行）`SIS.estimate` 抛 `TypeError: unsupported operand type(s) for *: 'NoneType' and 'int'`——是 pinned estimator 在这些输入下的内部错误（lgsa 模拟对"no finite estimate"路径未处理），**已按任务要求保留失败原因，未用手工数字放行**。处理建议（待验证）：换 norm=euclidean 重跑，或固定 estimator 上游修复后重跑。
- **成功项（n=512）**：SIS 只有 lattice 攻击产出有限值（2^18.0–2^39.1），master-LWE 含 dual/usvp/bdd。**结构性发现**：
  1. m/n=8 时 master-LWE 的 dual 无有限估计（样本 n < 秘密维 7n），成本由 usvp 主导（2^75–2^335）——公开变换这条攻击路径被显著抬升；
  2. **新的瓶颈是 SIS lattice**（2^19.9–2^39.1）：`planned_large_row` 的 γ1/γ2 规划随 m 线性放大，导致 SIS 范数界 d=2γ2+2κβ1 随 m 同步膨胀，SIS 难度不升反降；
  3. q 从 2^61 升到 2^77 时 m/n=4 行的 master-LWE 不升反降（dual 2^79.1→2^56.1）——公开变换成本对 q 的依赖非单调，筛选不能凭直觉。
- **成本模型与范围**：ADPS16+lgsa 是启发式；SIS 估计只覆盖实现的格攻击族，不覆盖所有 IBS 攻击；脚本本身声明这些数字"不能说明的内容"（见 limitations）。

## 5. 公开攻击负对照（本轮重跑）

`public_forgery_controls` 再跑：**r1-tiny 与 m2-functional 两行均 `equivalent_master_recovered=true`、`forged_signature_accepted=true`**（候选枚举 6561=3⁸，受害 Extract/Sign 查询 0）。弱行仍可被公开恢复并伪造——负对照继续有效，排除这两行的证据未变。

## 6. 最多 3 个"下一轮继续验证"候选（研究候选，非安全批准）

| 候选 | 参数 | 现状 | 待补 |
|---|---|---|---|
| **C1: g8-n512-k256-c64-q77** | n=512, m=4096, k=256, κ=64, q=next_prime(2^77) | challenge 268 bits；master-LWE usvp 2^334.6/2^303.7（充分）；**SIS 仅 2^26.6/2^24.1（不充分）** | 收紧 γ1/γ2 规划使 SIS 界硬化（主 AI 设计新筛选规则后重跑） |
| **C2: g8-n256-k192-c48-q61** | n=256, m=2048, k=192, κ=48, q=next_prime(2^61) | challenge 200 bits；master-LWE usvp 2^185.1/2^168.0（较充分）；SIS 工具失败待重跑 | 换 norm=euclidean 或修 estimator 后补 SIS；尺寸最小（pk 4.4 MB） |
| **C3: g4-n512-k256-c64-q61** | n=512, m=2048, k=256, κ=64, q=next_prime(2^61) | 唯一"m/n=4 且 master-LWE 到 2^79"的行；SIS 2^19.9（弱） | 作为工具链 canary：先修 γ1/γ2 规则，观察 SIS 能否随 γ 收紧而抬升 |

三者的共性缺口：**γ1/γ2 规划规则是 SIS 坍塌的根因**——`planned_large_row` 为 ~10 次拒绝试验设计、随 m 线性放大，必须改成"γ2 与 q 挂钩（γ2 远小于 q^½ 量级）、拒绝采样预期次数与接受率显式计账"的新规则。这是主 AI 的参数设计任务，本轮不做展开。

## 7. 给主 AI 的接口/实验输入

对每个候选：
1. **接口/补测**：候选均超出当前 MATRIX-REF/1 参考实现的可编码范围（q>uint32、γ2>2³¹），需主 AI 扩展研究配置（uint64 模数、大系数编码）或先做纯算术筛查；
2. **缺的安全估计/映射**：C1/C3 缺"γ1/γ2 重设计后的 SIS 重估"；C2 缺 SIS 估计本身（工具失败）；三者都缺 master-LWE 完整归约（当前只是单列公开变换的区分/搜索成本，不是伪造归约）；
3. **能否作为 Wang IBS 前提的研究候选**：能作为"参数研究入口"（Theorem 1 的 ROM UF-CMA 前提依赖合法 SIS 参数，当前不满足）；**不能**据此声称满足 Wang 前提；
4. **与 CHKP 组合前必须等待**：CHKP T4 后端与契约（不变）；且 IBS 侧必须先产出"公开恢复筛查通过 + SIS/master-LWE 双侧达标"的参数，才谈组合集成；
5. **不能作出的结论**：任何安全位数、任何"合法参数"认定、任何后端准入——全部保持 `security_claim: none / backend_admitted: false / parameters_are_formal: false`。

## 8. 出处、命令与限制

- 驱动脚本：`C:\Users\A\AppData\Local\Temp\luo_grid_ext.py`（WSL 路径 `/mnt/c/Users/A/AppData/Local/Temp/luo_grid_ext.py`）；结果 JSON：WSL `~/luo-grid-ext.json`。
- 运行命令：`cd /mnt/c/Users/A/OneDrive/文档/IB-ME-from-HIBE-IBS && PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -B /mnt/c/Users/A/AppData/Local/Temp/luo_grid_ext.py`；耗时 1239.7s；退出码 0。
- 复用仓库函数：`luo_parameter_screen.py` 的 `planned_large_row`（L43）、`screen_row`（L88）、`master_recovery_lwe_input`（L120）、`public_forgery_controls`；estimator commit L26。
- 论文位置：Luo Theorem 1 p.8（d=2γ2+2κβ1）；Algorithms 1–4 p.7。
- 限制：5 行 SIS 估计失败（estimator 内部 TypeError）已如实记录；所有 rop_log2 为启发式成本，不代表安全证明；本报告未产出合法参数、未修改仓库、未提交。
