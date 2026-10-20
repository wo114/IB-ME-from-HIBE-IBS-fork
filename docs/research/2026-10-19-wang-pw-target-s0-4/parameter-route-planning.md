# Wang–PW 参数路线的条件成本与资源检查（WIP）

2026-10-20；规划实现 `fb919a3`。本文件记录独立于服务器签名诊断的廉价规划，未改现有
`n512/q4294967291/s0=4` 参数或原钥，未新增服务器实验。完整目标仍包括签验、恢复、固定服务、
真实组合、CLI与完整安全参数；本文件不宣布其中任何一项由规划完成。

## 输入性质与实际执行

原文映射及缺失条件见[参数完成条件审计](parameter-completion-audit.md)。这里为了判断
“扩大q是否值得实施”采用以下**未经认证的规划假设**，不是从论文获得的有限安全参数：

```text
w=n*k, m=2w, M=3w, s0=4
g_root=4*ceil(sqrt(w)), s=8*g_root, s'=512*w
B=ceil(s'*sqrt(M)), B_ref=B
L_plan=ceil(s*(sqrt(m)+sqrt(w)))
beta_plan=ceil(2*B*sqrt(1+L_plan^2))
q=largest_prime_below(2^k)
```

L_plan只有渐近数量级动机，**没有认证谱常数或有限坏事件概率**；B_ref也没有在此认证。
不能把这些量放进正式参数报告并称已满足原文条件。脚本用整数比较精确计算所有根式向上取整，
逐点核q的素性与bitlength；精确算术只消除计算舍入，不能认证输入假设。

已实际运行[公开九点回执](evidence/parameter-planning/planning.json)：固定
estimator `53da5982597709ba0fdf94ea37a84d822310fd84`，只调用
`SIS.lattice(SIS.Parameters(..., norm=2), red_cost_model=RC.MATZOV)`。
每点独立子进程、最长60秒，无密钥或签名，9个子进程均退出0，源码与工具运行前后哈希一致。
norm2路径忽略shape model；没有声称额外GSA/LGSA或量子成本已评估。

## 观察结果

| n / k | beta_plan/q（约） | 单工具log2(rop) | 三份裸稠密阵列 |
|---|---:|---:|---:|
| 512 / 32 | 1.096e6 | 输入拒绝 | 54 GiB |
| 512 / 54 | 0.9710 | 43.03 | 153.77 GiB |
| 512 / 64 | 0.001452 | 43.27 | 216 GiB |
| 1024 / 64 | 0.008167 | 65.26 | 864 GiB |
| 2048 / 64 | 0.04632 | 121.04 | 3456 GiB |
| 4096 / 64 | 0.2613 | 241.97 | 13824 GiB |
| 4096 / 80 | 6.973e-6 | 304.97 | 21600 GiB |
| 512 / 192 | 6.624e-41 | 92.75 | 1944 GiB |
| 1024 / 96 | 5.248e-12 | 92.75 | 1944 GiB |

表中数值是**一项攻击在假设输入下的成本读数，不是IBS安全位数**，没有通过全攻击或正式参数准入。
最后两点具有相同w，因此本规划给出相同m、beta和阵列尺寸；增大q的位数同时减少n不能自动提高该工具成本。
较高成本行也没有因此满足所有论文/归约条件；回执另列必要检查 `q^2>n*beta^2`，
它为真仍不替代所选定理的完整有限条件。当前k32行使用L_plan，和原先乐观L=1得到beta=5260239171
的[已配置包络拒绝](evidence/local/parameter-screen.json)是不同输入，两份失败均保留。

资源列为 `3*M^2*8`，只有工作阵列的裸字节数；不含公私钥、分配器、QR/LAPACK工作区，不能当峰值RSS。
现后端另有q32哈希/模乘/公钥编码、4 GiB对象、65535签名维数等门；这些点没有被注册成可运行profile。
宽q公钥的u32计数会低估尺寸，回执另外给k-bit打包下界；该下界也不是已实现的宽q序列化。

## 对后续路线的约束

1. **现有n512原钥的工程诊断仍独立推进。** 最大GS门不能保证逐坐标sigma和中心资源门成立，
   详见[实际失败与公开探针](README_zh-CN.md#16-单次诊断终态与资源门定位)。修复该问题能改善研究签验，
   不会消除当前SIS输入拒绝。
2. **不能只改大q后启动目标实验。** 通过beta<q也可能只有较低工具成本；较大维度行已远超现稠密路线的
   110 GiB门。本表没有找到同时认证所有条件、满足目标成本且可由现后端运行的参数。
3. **后续可研究的实现方向**是选定现成有限参数条件后，评估直接使用用户G-trapdoor的论文支持采样实现、
   更宽精确模运算及流式对象，避免构造完整M维稠密核基。它们尚未实现或验收，不能称优化已完成，
   也不能承诺只换采样器就满足128GB预算。用户G-trapdoor本身的系数存储也需另算。

本表只排除了所列规划点在**当前稠密实现与证据条件下**作为已完成正式参数交付，
没有证明所有Wang参数或所有实现路线不可能。下一步仍须落实已有文献的有限谱/范数界、
采样与中止预算、全适用攻击和实际资源；不新增s0=2有限论证或基础安全归约。

## 验证与交付

[实现入口](../../../experiments/research/wang_pw_target/plan_parameters.py)与
[专项测试](../../../tests/test_wang_pw_target_parameter_planning.py)已提交。
23项新测试＋5项既有筛查测试为[28 passed / 0 failed/error/skip，6.648 s](evidence/parameter-planning/tests.xml)，
包括固定真实工具的拒绝与成本返回；不是目标算法实跑。
[命令与源码绑定](evidence/parameter-planning/review.json)、[日志](evidence/parameter-planning/tests.log)与
[manifest](evidence/parameter-planning/manifest.json)可离线检查，JUnit只脱敏一个本机hostname。

始终保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、
`nist_security_category=null`。未推送或创建PR，完整大目标未完成。
