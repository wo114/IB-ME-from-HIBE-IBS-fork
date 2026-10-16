# SRGG：经典理想 XOF、均匀目标身份与有界公开采样

2026-10-16。继续用户确认的 **SRGG 原生 strong** 目标；本批完成 seed/XOF 嵌入的条件同分布引理、保留失败的公开 pair、直接均匀目标身份的经典条件归约，以及实际有界公开 Gaussian 采样器。新增成果只在本地提交；按用户最新决定，**与 HIBE 无关的完整工作完成后才统一 fork＋PR 推送**。六项目标仍 active/WIP。

本批不修改上一批 [63ea9fc reduction](../2026-10-16-srgg-reduction/README.md) 或更早 [n512 bridge](../2026-10-16-srgg-bridge/README.md)；不更换 strong 赢法或用认证转换替代。它没有建立实际 IBS/QROM 安全定理、正式参数准入或大维公共服务。相关工程与困难性估计另批继续。

## 可审查结果

| 部分 | 具体结果 | 证据 |
|---|---|---|
| seeded 公共矩阵 | 对外部均匀 Ahat 编程完整原始拒绝采样字节流；均匀目标平均后，包含 Setup abort、缓存与所有前后缀的联合 law 精确匹配诚实 ideal-XOF | [seeded-xof.md](seeded-xof.md)、[seeded-xof.json](seeded-xof.json) |
| raw 门与失败 | 在 `(U,E,Y)` 上保留 raw/final 两个门；失败仍保留 h；公开 pair 与 uniform-target 条件 key pair 的 TV 恰为像的 TV | [public-pairs.md](public-pairs.md)、[public-pairs.json](public-pairs.json) |
| 目标身份 | 以全 uniform-H1 诚实参考和隐藏 J 做成功事件耦合；绕开 image-distributed SIG.Gen，显式支付身份像、目标首次失败、GoodKey、别名、两端有限签名和所有 oracle 损失 | [direct-ibs.md](direct-ibs.md) |
| strong 与困难性 | 对完整公开 owner/fork 提取器，先用 Jensen 处理平均实例成功率，再对整个提取器作16列 shared-Ahat Module-LWE hybrid，终点为确切 HNF-MSIS `[I_2|U_(2×19)]` | [direct-ibs.md §6–9](direct-ibs.md#6-从-native-strong-到同一个短核矩阵)；这仍是条件不等式 |
| 有效公开采样 | 实际实现公开 U、Sim z、均匀 E 与精确二元 c；复用冻结的有限 scalar/aggregate 组件，不重抽整组，不读取主陷门，明确字节硬上限和 abort | [effective-samplers.md](effective-samplers.md)、[reduction-samplers.json](reduction-samplers.json) |

raw-XOF first-touch 包括仅读1B或后缀的查询；不能先返回 bytes 再改 H1/H2。H2 不含 id，owner 跨身份处理已明确。目标 Sign 失败不能留下未返回签名的 sign-owner。所有这些约束属于完整归约的实质前提，不能只引用一个 TV 数字替代。

## 数字的适用范围

沿用研究点 `n512,d2,w8,p16383,b31,r²64,Q13972913866395903,L16`；不是正式参数。均匀 HNF-MSIS 终点的系数矩阵为1024行、10752列负循环块结构，差分欧氏范数平方至多 `953022385920644398085744640`、逐系数无穷范数至多 `30871060654286`。不能把它当作条目独立均匀的标量矩阵。

根矩阵 raw rejection 最坏消费3,670,016B，小于8,388,608B read budget，失败 `<2^-1278`；单身份失败 `<2^-1279`。这些是理想独立 XOF bytes 下的界，Public 重算同一点不重复计失败。公开 U/z 的 n512 deep product batch 各含 abort 的 TV `<2^-177`；字节硬上限分别11,104,872B和13,744,738B。E 的全路径524,288B、abort/TV `<=2^-3574`；c512精确均匀需64B。

这些数值不授予安全强度。完整底层假设、复合 Q、结构攻击与归约损失的困难性估计另行推进；Kyber/ML-KEM、NIST 仅为比较目标。当前条件归约还未给实际 adaptive 程序、conditional raw-prefix 有界生成器、完整持久服务与全局资源账本的全部对应。

## 验证与复现

指定 WSL Sage10.9/Python3.13.15 最终回归 **799 passed，0 failed/errors/skipped**。Windows Python3.14.7 的两个纯 Python 新文件共 **42 passed**。独立审查另跑 seeded21、public-pairs21、reduction-samplers53；这些与799项回归重叠，不相加为独立检查数。准确命令、环境、原始/公开收据映射见 [validation.json](validation.json)。

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_*.py tests/test_primitive_spec_audit.py --junitxml=build/outputs/srgg-classical-rom-recheck/sage.junit.xml
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.reduction_samplers --output build/outputs/srgg-classical-rom-recheck/reduction-samplers.json
python -m experiments.research.candidates.srgg.seeded_xof --output build/outputs/srgg-classical-rom-recheck/seeded-xof.json
python -m experiments.research.candidates.srgg.public_pairs --output build/outputs/srgg-classical-rom-recheck/public-pairs.json
```

以上向新目录重放，避免覆盖原始收据。n512 新公开 sampler 本批只构造零熵证书；小维 U/z/E/c 测试实际调用 sampler，未输出私有样本。有限 law 工具不使用真实身份或消息、没有随机重复次数；它们的确定性穷举不是密码学攻击。没有重跑旧 n512 生命周期。主机 Intel Core Ultra7 255HX，WSL2可见20逻辑CPU，未固定频率/亲和性；精确软件环境见收据。没有安装依赖。

只读完整性检查，重核本批及冻结 reduction/bridge，**不会重跑测试**：

```text
python experiments/research/srgg_classical_rom_delivery_check.py
python -O experiments/research/srgg_classical_rom_delivery_check.py
```

清单见 [MANIFEST.json](MANIFEST.json)。公开 JSON 按字节复制；JUnit仅移除 hostname 并统一LF序列化，原始收据保留在 `build/outputs/srgg-classical-rom-2026-10-16/`。文稿给出的普通数学推导不是机器形式化证明；source/实现/有限测试和参数安全估计分别承担各自证据范围。

```text
security_claim=none
backend_admitted=false
parameters_are_formal=false
nist_security_category=null
```

后续继续完成独立原语接口、严格对象/持久服务、实际模拟与预算、量子模型、困难性参数和相应真实验收；HIBE 选择不进入这些任务。本批 local commit 不代表这些剩余内容完成，也不提前推送。
