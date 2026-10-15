# C3：Xie NTRU 修订方程研究核（WIP）

实现提交 `7c139f4a064071bc8e13c95c50eecd88765a62d5`，基点 `8ba7ebf`。
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
- n16/n32 两档各1次系统随机：同根两个64 B身份、32 B消息、32份新签名；
  原实例新进程各32次零熵恢复验签、两个恢复SK各生成1份新签名；没有替换根或外循环重试。
- 原四类对象各5种畸形编码全部拒绝；每档32次错身份/改消息/改签名观察均拒绝。
  同时每档均找到模 q 平移的新有效签名及实际默认 lambda4 的公开零挑战伪造；没有用正常负例掩盖这些反例。
- 仓库外独立 wheel/site 复用上述两个原实例：64次零熵验签、4个原SK新签名通过，
  记录的30个运行 provider 全来自隔离 site；原二进制状态全部保持原字节。
- Lai 资格路线独立15 passed / 0 skipped；Windows C与目录测试60 passed / 33 Sage缺环境skip；
  Windows公共框架427 passed / 5 skipped，状态partial。交叠执行不相加计数。
- 开发失败：首次线程池新发钥2项失败（Sage/PARI SignalError）；其余48项通过。
  后续明确拒绝不支持的线程调用后，53项全部通过，未声称并行新发钥。

开发测试用 `DeterministicRandom` 的 TEST 熵；实物探针逐次读取系统 CSPRNG，不复制固定测试根。
公开 TEST 向量的[来源和重放入口](../../../../tests/fixtures/xie_study/README.md)与实物分开。
无新原生依赖，复用现有有限 Gaussian/GPV 工具；没有修改这些工具或 B 成员文件。

| 单次实物 | n16 | n32 |
|---|---|---|
| Setup s / 根尝试 | 0.044 / 1 | 0.162 / 1 |
| 两身份提取 s | 0.099 | 0.931 |
| 研究JSON签名 B（32份范围） | 362–379 | 591–608 |
| 父进程实际熵 B | 675130 | 1140209 |
| 实物总时 s | 4.519 | 5.890 |
| 公开零挑战搜到的第几条消息 | 1901 | 219520 |

父进程熵不含新进程恢复SK签名的独立新熵，子进程收据另列。总时含文件、攻击与子进程，
两档每档只有1次重复、同机同时运行其它检查；尺寸是此研究JSON格式，不能作为等安全性能比较。

环境：WSL2 Linux6.18.33.2、Intel Core Ultra9 275HX、规定 Sage10.9/Python3.13.14；
Windows Python3.14/setuptools84 构建 wheel，1288988 B，SHA-256
`456482482e338ac14a7e44ff0202b735c2075a665960d97a503f6d967c425d22`。
38份实际provider/测试/CI文件与实现提交的Git blob逐字一致；旧 experiments 导入有兼容别名，
按实际 `ibme.lattice` provider 文件核对，见[来源核验](evidence/source-check.json)。
原始[JSON/XML/日志与隔离脚本](evidence)公开保留；没有复制私钥、主状态、采样几何、wheel或二进制。

复验（WSL 仓库目录）：

```sh
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python ci/run.py run xie-ntru-ibs --output test-results/xie-study/primitive
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.xie.qualification
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.xie.probe --private-directory test-results/xie-study/fresh16 --n 16 --source-commit 7c139f4
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.xie.probe --private-directory test-results/xie-study/fresh16 --restore-only
```

新运行必须使用新目录；32档改 `--n 32`。恢复命令复用原对象且禁止 Sage/私有执行模块和新熵。
私钥和主状态只写入忽略的本地输出目录，不进公开材料。状态保存是研究快照，不是已完成的持久发钥服务。
隔离重放见 `evidence/installed-check.py`：在仓库外先装入独立site，传入原探针目录及新的私有签名目录。

统筹范围只涉及 `ci/suites.json` 的独立路由阶段/测试及对应 CI 负控断言；
共同 registry、协议、CLI 和安全标记未改。C1 Lai 的类型/逆元资格问题另外交付。

剩余：作者澄清或经审定的修订规格、正式参数/公钥分布/有限误差与查询界、固定服务证明映射、
完整 IBSBackend/登记和真实 HIBE 配对、强 UF/量子模型及生产侧信道。功能测试和统计诊断不替代证明。

完整[本分支修改清单](files-changed.txt)。统筹跨边界只同步独立CI及其断言、目录/状态/任务登记；原语、框架和安全状态分别报告。
