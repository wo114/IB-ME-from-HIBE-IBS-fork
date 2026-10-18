# SRGG 原表参数串行运行与资源记录（WIP）

来源：Jia、Liu、Tang、Wang，*Constructing Efficient Identity-Based Signatures on Lattices*，仓库冻结 [PDF](../../../../papers/2025_efficient_ibs_jia.pdf)，SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。本包只测独立 IBS 的 Python/Sage 原顺序 `SourceSchurBackend`；不涉及 HIBE。保持原 Table 4 的 `n=512, p=16383, b=31, w=2, Q=15744063, d=2/3/4` 及原 `γ`。本批选择代码明确标记的 *table-standard-deviation* 解释，论文是否意指该解释仍未定。

每档在独立 WSL Sage 进程中串行运行 3 次新的 Setup、Alice（5 B）发钥、32 B 消息签名与验签；每次使用 `SecureRandom`。随后对最后一份诚实签名额外重复验签 1000 次。三档全部诚实验签通过。时间是本机 Python/Sage 墙钟中位数；RSS 是**整个进程**的峰值，无法归因到单一算法。主机未隔离其他负载，因此这些数字只是可重跑的本地记录。

| 原档位 | Setup / s | Extract / s | Sign / s | 重复 Verify / s | 进程峰值 RSS / KiB |
|---|---:|---:|---:|---:|---:|
| PARAM-I | 0.521 | 2.171 | 2.635 | 0.00961 | 241600 |
| PARAM-II | 1.290 | 4.053 | 4.651 | 0.0217 | 272140 |
| PARAM-III | 3.298 | 7.295 | 9.442 | 0.0354 | 313944 |

逐次耗时、CPU 时间、重试次数、环境与未压缩对象字节数见 [I](param-i-table-sd.json)、[II](param-ii-table-sd.json)、[III](param-iii-table-sd.json)。代码入口为 [`paper_runtime_benchmark.py`](../../../../experiments/research/candidates/srgg/paper_runtime_benchmark.py)。三档签名尝试数分别是 `1,2,1`、`1,1,1`、`1,1,2`；三档 Setup 均每次一次成功。固定签名的 1000 次重复验证不等同于 1000 个独立签名。

原论文 Table 6 的数据来自 C/gcc 8.3.0、Deepin 20.9、单核 i7-10710U 与每算法 1000 次中位数；Table 7 的长度使用 rANS。这里没有作者 C/rANS 程序、编码表或同硬件复现；本包的 3 次 Python/Sage 原语运行、未压缩对象大小**不能与论文表中的性能或长度直接比较**，也不是公平优化评测。`author_C_rANS_implementation_reproduced=false`、`author_1000_run_median_reproduced=false`。进一步复现作者结果需要原 C 源码、具体 rANS 频率表和对应运行环境；目前只核到论文自述，不能补造。

在仓库根目录的规定 WSL Sage 环境重跑（输出路径须尚不存在）：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_runtime_benchmark --profile PARAM-I --cycles 3 --verify-calls 1000 --output /tmp/srgg-param-i-runtime.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_runtime_benchmark.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python docs/research/team-b-delivery/2026-10-18-srgg-serial-runtime/verify_delivery.py
```

[验收记录](validation.json)固定本轮命令和摘要；[清单](MANIFEST.json)用于校验源码、测试与回执。测试为 **2 passed**。这是功能与资源证据，不构成分布证明、困难性证明或安全准入：`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`。
