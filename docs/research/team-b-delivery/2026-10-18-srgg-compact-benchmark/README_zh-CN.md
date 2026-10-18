# SRGG 原表紧凑编码与内存、时间实测

论文：Jia、Liu、Tang、Wang，*Constructing Efficient Identity-Based Signatures on Lattices*，DOI `10.1049/ise2/6684889`。本批为既有原表实现增加无损传输／快照编码，并测量实际资源；不是新签名方案或作者 C/rANS 性能复现。[English](README.md)。

## 已交付

可选 [compact v1 格式](../../../specs/srgg-paper-compact.md) 覆盖 public、master（含发钥缓存）、user key 和 signature，严格解码后返回原对象。原 JSON `to_bytes()`、公钥 context、H1/H2 输入、采样源码、原参数、范数门与默认 FixedIssuer 存储均未更改。

编码采用固定 24-bit 公共模系数、2-bit CBD1 witness、精确有符号 zigzag 整数和 1-bit challenge；没有模约减签名响应、尾截断、量化或重抽样。版本、对象类型、论文指纹、参数解释和公钥上下文均显式绑定。身份排序、pending/failed/issued 状态、最小位宽、padding、截断／追加及 2 MiB 容量均检查。该 Python 编码不是常数时间实现，也不加密私有快照。

## 同对象编码实测

以下是各档 3 个独立 SecureRandom 根的中位数，单位 **B**。JSON 与 compact 来自完全相同的四个对象；用户密钥包含公钥，master 包含公钥、witness 与一个已发用户缓存。因此下表是完整封装，不与论文纯分量尺寸混排。

| 原表 | 公钥 JSON → compact | master JSON → compact | 用户密钥 JSON → compact | 签名 JSON → compact |
|---|---:|---:|---:|---:|
| PARAM-I | 34,463 → 12,374 | 102,606 → 20,306 | 84,165 → 18,256 | 35,368 → 13,400 |
| PARAM-II | 76,954 → 27,734 | 218,520 → 41,106 | 176,919 → 36,496 | 51,117 → 19,288 |
| PARAM-III | 136,433 → 49,238 | 377,344 → 69,074 | 303,453 → 60,880 | 67,076 → 26,264 |

配对比值中位数：公钥约 2.77–2.79 倍，用户密钥 4.61–4.98 倍，master 5.05–5.46 倍，签名 2.55–2.65 倍。各独立状态的原始字节与范围见 [wire.csv](wire.csv) 和 [benchmark.json](benchmark.json)。这些不是 512 倍的环矩阵槽位比。

## 时间与内存

原表固定 `n=512,p=16383,b=31,w=2,Q=15744063,d=2/3/4`，采用既有 `table-standard-deviation` 解释与默认数值精度。身份 64 B、消息 32 B。每档 3 根，每根一次 Setup、一次 Extract、首签及三轮 warm 签验。Backend 不缓存 Schur plan，warm 仍包含原代码的准备和采样。下表先取每根 warm 中位数，再对三根取中位数，单位 **秒**：

| 原表 | Setup | Extract | 首签 | warm 签名 | warm 验签 |
|---|---:|---:|---:|---:|---:|
| PARAM-I | 0.522202 | 2.144220 | 2.490755 | 2.504978 | 0.009441 |
| PARAM-II | 1.389869 | 3.801864 | 4.864011 | 4.857877 | 0.020839 |
| PARAM-III | 3.174095 | 6.828144 | 8.965721 | 8.822885 | 0.034445 |

每根再分别开启 JSON／compact 新进程恢复四对象，零新发钥熵复用缓存密钥，并用新 SecureRandom 重签。冷进程包含导入和文件读取；OS 页缓存保留。两种恢复顺序按根交替。整进程时间还包含恢复检查和一次新签名，不能称为单独解码时间。

| 原表 | 生成进程树 RSS 中位数／最大 MiB | JSON 恢复 RSS 中位数 MiB | compact 恢复 RSS 中位数 MiB |
|---|---:|---:|---:|
| PARAM-I | 238.055 / 238.121 | 234.750 | 234.637 |
| PARAM-II | 267.289 / 334.172 | 261.992 | 261.887 |
| PARAM-III | 307.320 / 307.691 | 299.680 | 299.156 |

RSS 由父进程每 10 ms 读取 `/proc` 进程树；可能漏短峰，树求和可能重复共享页，不是物理内存上界。另保留每个 worker 的 Linux 自身 `ru_maxrss` 生命周期峰值，不相减当作独占阶段内存。PARAM-II 的 334 MiB 例发生在导入阶段，包含瞬时子进程；保留未剔除。生成进程还包含两种编码的测量，不能当作纯 sampler 内存。详细阶段、样本及冷进程结果见 [memory.csv](memory.csv)、[timings.csv](timings.csv)、[tables.md](tables.md)。

**文件缩小没有带来相同比例的算法 RAM 降低。** 解码仍恢复原 tuple／Sage 对象。当前完整 compact API 也更慢：例如 PARAM-I 用户密钥 JSON／compact 编码为 0.462／14.169 ms，解码为 15.062／32.318 ms；PARAM-III 对应 2.283／59.507 ms 和 68.102／151.939 ms。API 包含各自实际执行的语义验证及规范重编码，不能当作纯 bit-pack 算法速度比较。冷恢复墙钟的差异也未在三档稳定呈现同一方向，不声称整体加速。

## 执行与验证范围

- 环境：Intel Core Ultra 7 255HX，WSL2 Linux 6.18.33.2，Sage 10.9／Python 3.13.15，OMP／OpenBLAS 各 1 线程；逐个 worker 串行执行，其他宿主工作及 CPU 频率未隔离。
- 固定日程：9 个独立根，9 个生成进程、18 个恢复进程，27/27 通过；54 次成功签名，72 次显式验签（另有原 sign 内部自检）。495 项功能检查含重复 codec 往返，不是 495 次独立安全实验。
- 每对象先一次未计时往返，再交替测两种格式各 5 轮编解码；codec 期间拦截 SecureRandom，零取熵。所有内部 Setup／Sign 重试维持原 64 上限并记录实际次数；没有外部补跑、筛根或丢弃失败样本。
- 启动前后均为源码提交 `87f572a1a7636a8b83c9e693ebe359ef185d2d92`，122 个源码／原文文件哈希在计时前后一致。新编码及原后端相关测试 **183 passed**。开发 smoke 独立于最终日程，不计入上述 9 根。
- 公开包只含配置、布尔、尺寸、时间／RSS、计数和源码指纹。真实对象、随机源、私有文件及其哈希不发布。原 JSON 默认固定服务的锁／fsync、容量与迁移未更改，也未计入本轮原语实测。

完整数据以 [benchmark.json](benchmark.json) 为准；[provenance.json](provenance.json)、[validation.json](validation.json) 和 [MANIFEST.json](MANIFEST.json) 固定本批范围。只读校验无需 Sage、不取熵：

```text
python docs/research/team-b-delivery/2026-10-18-srgg-compact-benchmark/verify_delivery.py
python -O docs/research/team-b-delivery/2026-10-18-srgg-compact-benchmark/verify_delivery.py
```

实际重跑须使用新输出目录，私有目录必须位于忽略的 `build/outputs`：

```text
PYTHONPATH=src:. OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.compact_benchmark --private-directory build/outputs/srgg-compact-repeat/private --output build/outputs/srgg-compact-repeat/public/benchmark.json --source-commit <运行代码的40位提交> --repetitions 3 --warm-repetitions 3 --codec-repetitions 5
```

只需重建汇总表时运行 `render_tables.py`，不重跑采样。格式 API 见契约；HIBE、全局 registry／CLI 与默认服务迁移不在本批。旧 frozen sampler、原 Table 4 和 JSON context 保持不变。安全标记继续 `none/false/false/null`；本批完成无损编码和限定环境实测，不宣称新增安全等级、分布定理、作者 C/rANS 重现或同等级方案优势。
