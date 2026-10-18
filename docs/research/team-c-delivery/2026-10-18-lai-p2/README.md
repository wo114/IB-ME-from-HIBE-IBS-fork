# C1 Lai P2：A 参数点探针与 4 字节系数（WIP）

状态：**P2 前置探针完成，尚未接入 registry/CLI**。`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。本批只证明“A 点（n=256、t=1）能在研究参数下完成两级生命周期，并解决 32 B seed 容量与 86 B 身份绑定”，不构成安全/目标参数声明。

## 1. 结论

**A 点可行，B/通用 t 不需要为 P2 先做。**

- `n=256, t=1, q=2147484161, k=32, l=2, p=2, σ=2`：两级加解密、32 B 消息、4 字节系数序列化通过。
- 5 个随机种子完整生命周期 **5/5**，平均 **26.29 s**（18.08–28.84 s）。
- 容量 `k·n = 8192 bit = 1024 B`，32 B seed 足够；身份每层 256 bit（86 B 输入哈希到 256 bit，碰撞约 128 bit）。
- 与 B（n=16,t=16）相比，A 不需要改身份向量/公钥/掩码结构，P1 的 `t=1` 代码直接换参数即可；运行时间在可接受范围。

## 2. A 点探针

固定 `n=256, l=2, p=2, σ=2, depth=2`，扫三个 `q≡1 mod 512` 的素数；每个点跑一次完整生命周期（32 B 消息）。

| q | k | tolerance | level 1 | level 2 | 备注 |
|---|---|---|---|---|---|
| 1,073,750,017（2^30+8193） | 31 | 248,524,837 | 通过 | **失败**：残差 279,958,552 > 容差 248,524,837 | 差 13% |
| 2,147,484,161（2^31+513） | 32 | 497,046,000 | 通过 | 通过 | **选为 A 点** |
| 4,294,968,833（2^32+1537） | 33 | 985,333,427 | 通过 | 通过 | q>2^32，需 5 字节；不选 |

A 点单次计时（q=2,147,484,161）：

| 阶段 | 时间 | 备注 |
|---|---|---|
| setup | 0.19 s | `a0^T R + a1 = g` |
| extract（level 1） | 3.16 s | R1 max width 670 |
| derive（level 2） | 5.76 s | R2 max width 137,980 |
| encrypt level 1 | 3.61 s | |
| decrypt level 1 | 0.14 s | |
| encrypt level 2 | 9.66 s | |
| decrypt level 2 | 0.40 s | |
| 5 种子完整生命周期 | 26.29 s 平均 | 5/5 |

## 3. 代码与测试

新增/修改：

- `experiments/research/candidates/lai/backend.py`
  - `A_POINT_PARAMS = Params(q=2147484161, n=256, k=32, l=2, p=2, σ=2, σ_r=1, depth=2)`；
  - `Params.coefficient_bytes`：`q<2^24` 用 3 字节，否则 4 字节；`q≥2^32` 拒绝；
  - `_encode_ring`/`_decode_ring` 按 3/4 字节自适应；
  - `Params` 不再禁止 `q≥2^24`，序列化层再检查。
- `tests/test_lai_p1.py`
  - `test_a_point_capacity_and_identity`：32 B 消息、256-bit 身份、二进制系数；
  - `test_a_point_two_level_lifecycle_and_serialization`：A 点两级生命周期 + 4 字节密文往返。

结果：

```sh
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest tests/test_lai_p1.py -q
# 22 passed (23-28 s)

... tests/test_lai_p1.py tests/test_lai_qualification.py -q
# 37 passed in 24.87s
```

## 4. 这解决了 P2 的两个硬前置

| P2 前置 | A 点取值 | 结论 |
|---|---|---|
| 32 B seed 容量 | `k·n = 32×256 = 8192 bit = 1024 B` | 32 B 足够 |
| 86 B 身份绑定 | 每层 256 bit 二进制身份（SHAKE 输出） | 碰撞约 128 bit；86 B 输入不再压到 8 bit |
| 序列化 | 4 字节系数（q<2^32） | A 点 q=2^31 可用 |
| 结构 | `t=1`，P1 代码不变 | 不需要通用 t/B 分支 |

## 5. 未做与风险

1. **研究参数，不是目标参数**：q=2^31、n=256、σ=2 没有安全等级；P5 目标 n=1024 时仍需重新筛 q/σ 和估计。
2. **未接 registry/CLI/state**：`lai-ideal-hibe` 仍 `unavailable-v1`；HIBE 盘点仍 3/8。
3. **未做组合配对**：86 B 身份、32 B seed 只是容量满足；Wang 包装、`(rcv, phi)` 顺序、四种匹配、状态恢复仍未接。
4. **采样仍是 Klein，无 perturbation**：功能通过，不是证明级 `ringSampleD`；P5 或正式分布再处理。
5. **q=2^30 的边界很近**：A 点选 q=2^31 而不是 q=2^30；若换 σ/n 需重新扫边界。
6. **Sage 运行 26 s/生命周期**：P2/P3 原型可接受，P5 目标 n=1024 会更慢，需要 C/优化实现或减少重复次数。

## 6. 下一步（P2 继续）

1. 把 `lai-ideal-hibe` 接入统一 HIBE 对象/API/codec；
2. registry 登记（研究后端、明确 research 参数、`available=True` 但 `none/false/false`）；
3. CLI 选择/发钥/派生/加解密/状态恢复；
4. CI 套件与 catalog/docs 更新；
5. 然后 P3：接一个就绪 IBS，跑四种匹配/错配与恢复。

安全声明：本批是功能/工程验证，不是 PLWE/ring-SIS/HIBE/匿名的安全证明；测试通过不代表安全等级。
