# ABB 完整流程的精确算术修复（WIP）

先完成真实密钥与加解密，再做性能比较。此前 rootgs16/v3 的实际 Setup 已失败，旧 q104/v2 的原生子进程越过 8 GiB，两个失败实例和 FAILED 地址均保留；不在原实例修改宽度或重发地址。

本批增加整数 Bareiss/FLINT 引擎，替换规约质量检查和 GPV 预计算的逐项有理 GSO。GPV 的下降坐标顺序、精确中心、标量有限高斯、宽度、ToBasis、RandBasis、完整核格、方程/范数与中止条件保持。独立测试核对全部投影权重及同随机数的实际 GPV 样本，而非只检查范数。源程序、可移交构建脚本和依赖见 [native 工具](../../../../experiments/research/abb_rom/native/README.md)。

新的独立研究配置由完整公开充分条件计算：n=1，q=604462909807314587353111，根随机块160，m1=160，m2=480，总维度640，Hadamard scale35。预声明规范化根 GS²≤256（Setup 必须实际核验），R²=76800，sigma1²=70401895956480000，sigma2²=12391067385667587435134976000000000，tau2²=2379084938048176787545915392000000000000；epsilon64，error128，qalpha4，最多2²⁰次封装，身份86/86 B，载荷32 B，父/子地址容量各2。参数写入独立 v4 快照及上下文，不拼接旧实例。

选择256的输入依据仅是一份真实旧 AP09 根的只读算术诊断：95.245秒，16/64未满足，256满足；新私有随机调用0、发放密钥0、写原状态0。该诊断不保证新根通过，更不证明完整HIBE。新完整运行结果随后归档，不把当前公开条件通过计为实际密钥完成。

修复运行观察器只统计父进程的问题：现在保守累加实验主进程及所有原生子孙的 RSS，达到预声明8 GiB时中断整个实验树并保留 FAILED。共享页面每进程计数，故这不是去重的机器物理内存统计。收据同时绑定 Python 源码、原生程序源码与二进制哈希。

本配置是 n=1 教学研究负控；根质量拒绝事件及其条件化分布、正式高n参数、运行空间失败界、矩阵 RO 映射仍未闭合。ROM 工程实现，`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`；测试不能替代安全证明。完整 ABB 与 Luo 组合仍待真实流程后验收。

测试命令：

```sh
export PATH="$HOME/.cache/ibme-native-tools/flatter-d2b8026/bin:$PATH"
export IBME_EXACT_GRAM_EXECUTABLE="$HOME/.cache/ibme-native-tools/exact-gram-v1/bin/ibme-exact-gram"
export OMP_NUM_THREADS=8 OPENBLAS_NUM_THREADS=1
~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_abb_exact_gram.py tests/test_abb_normalized_root_profile.py tests/test_abb_flatter_reduction.py
```

实际结果24 passed，22.88秒。随后执行 `tests/test_abb*.py tests/test_matrix_finite_sampling.py tests/test_chkp_matrix_profiles.py`：170 passed、7 skipped，37.99秒。3项依赖尚不存在的完整真实ABB实例，另外4项依赖外部证据；跳过不计通过。JUnit收据见evidence。新实例收据随后记录。
