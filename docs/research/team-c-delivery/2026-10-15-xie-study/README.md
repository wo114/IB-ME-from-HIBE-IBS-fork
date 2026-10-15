# C3：Xie NTRU 修订方程研究核（WIP）

本批新增实际 NTRU 根生成、身份 Gaussian 原像提取、带拒绝的签名、纯公开验签和四类严格对象恢复。
这是独立的修订研究实物；[原文冲突与算法对应](algorithm-map.md)明确列出每项修订，
**没有计为 Xie 原稿复现、共同 IBSBackend、完整 HIBE 配对或已准入安全方案**。

两个研究域 n16/n32，q12289，根宽64、提取宽4096、签名宽65536、lambda4、M4；
完整限额见代码 `StudyParams`，默认每次根最多64轮、签名128轮、每操作熵64 MiB。
只用教学/研究参数，三个安全标记保持 `none/false/false`。当前挑战空间很小且已有公开伪造负控，
不能用于比赛材料中的安全等级声明。正式论文参数及模型映射没有冻结。

## 本次执行

- 规定 WSL Sage 环境的两份专项文件：53 passed / 0 skipped；覆盖真实整数 NTRU、
  两身份/多消息、GPV 方程、严格解析、Gaussian 诊断、拒绝/熵中止、pending 恢复、
  并发缓存及主线程前置限制、纯公开新进程验签、模 q 平移与公开零挑战伪造。
- 开发运行 n16 的系统随机同根双用户/32 新签名、原实例新进程32次零熵恢复及2次恢复SK新签名通过；
  本段为开发记录，固定代码版本后的原始实物收据另行补入。
- 开发失败：首次线程池新发钥2项失败（Sage/PARI SignalError）；其余48项通过。
  后续明确拒绝不支持的线程调用后，53项全部通过，未声称并行新发钥。

开发测试用 `DeterministicRandom` 的 TEST 熵；实物探针逐次读取系统 CSPRNG，不复制固定测试根。
公开 TEST 向量的[来源和重放入口](../../../../tests/fixtures/xie_study/README.md)与实物分开。
无新原生依赖，复用现有有限 Gaussian/GPV 工具；没有修改这些工具或 B 成员文件。

复验（WSL 仓库目录）：

```sh
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python ci/run.py run xie-ntru-ibs --output test-results/xie-study/primitive
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.xie.qualification
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.xie.probe --private-directory test-results/xie-study/fresh16 --n 16 --source-commit YOUR_CODE_COMMIT
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.xie.probe --private-directory test-results/xie-study/fresh16 --restore-only
```

新运行必须使用新目录；32档改 `--n 32`。恢复命令复用原对象且禁止 Sage/私有执行模块和新熵。
私钥和主状态只写入忽略的本地输出目录，不进公开材料。状态保存是研究快照，不是已完成的持久发钥服务。

统筹范围只涉及 `ci/suites.json` 的独立路由阶段/测试及对应 CI 负控断言；
共同 registry、协议、CLI 和安全标记未改。C1 Lai 的类型/逆元资格问题另外交付。

剩余：作者澄清或经审定的修订规格、正式参数/公钥分布/有限误差与查询界、固定服务证明映射、
完整 IBSBackend/登记和真实 HIBE 配对、强 UF/量子模型及生产侧信道。功能测试和统计诊断不替代证明。
