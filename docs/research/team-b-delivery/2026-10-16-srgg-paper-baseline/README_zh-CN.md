# 格上的高效基于身份签名构造：SRGG 原参数复现

**原题：** Constructing Efficient Identity-Based Signatures on Lattices。
**作者：** Huiwen Jia、Ying Liu、Chunming Tang、Lin Wang。
**单位：** 广州大学信息安全重点实验室、广州应用数学中心，以及成都通信安全技术实验室，中国。
**来源：** IET Information Security (2025)，[DOI 10.1049/ise2/6684889](https://doi.org/10.1049/ise2/6684889)。原文 CC BY。
**摘要译述：** 原文研究格签名与逆像采样，提出理想格上的紧凑 IBS；先给出椭球版本的 G+G 签名，再适配逆像采样得到 IBS，给出 QROM 安全论证、三组参数及概念验证实现。此段是来源说明，不代表本仓库已复现其全部安全或性能结论。

## 本批实际结果

2026-10-16。**原论文三组输入的独立功能基线已完成；正式安全准入未完成。**
两种 Gaussian 解释共 6 轮固定测试随机数运行，另有 PARAM-I 的 1 轮系统随机数运行；每轮 1 根、1 身份、2 次签名，各 37 项检查通过。
128 项新增测试和 93 项相关回归共 **221 passed、0 failed、0 skipped**；不把独立重复核验再累加。
实现提交 `e9736f28ba907be28ca0bf13a27b9e67187b0bab`，详见 [validation.json](validation.json) 和两份 JUnit。
当前仅本地提交，未 push、未更新 PR37。

此前优化、w8/r²64、factor2、条件证明及失败记录完整保留；本提交只新增 13 个代码/测试文件，没有改删既有 tracked 文件。
[SOURCE_MAP.md](SOURCE_MAP.md) 给出原文页码、Table 3/4 和 Algorithms 1–8 的对应。

## 参数、解释和实现边界

三组共同 `n=512,p=16383,b=31,w=2,Q=15744063,r≈1.16`，模块秩为 2/3/4；四列宽度和 γ 保留原文数字。
默认 `table-standard-deviation` 把报告数字当物理标准差，内部 shape 为 `2πs²`；`literal-density-width` 使用 `s²`。
**作者未确认默认解释，r 是发表的近似值。** 两种结果和对象各自绑定，不能混用。
原文没有固定 `e∈Z_p` 的整数 lift，本实现显式使用 `centered-mod-p`；HNF 使用 `centered-mod-Q`。
原文因子保留为 factor1，不加入旧 raw/user norm cap 或 `Q>2γ` gate，也不通过改宽度/γ掩盖失败。

代码在 `experiments/research/candidates/srgg/`：

| 文件 | 职责 |
|---|---|
| `paper_profiles.py`、`paper_parameters.py` | 原三组参数、作者结果单列、记号与模代表绑定 |
| `paper_algebra.py` | 环方程、域分隔 hash、HNF 与 2Q 恢复 |
| `paper_samplef.py` | 各向异性 joint Gaussian、精确有理环级数及有限误差记录 |
| `paper_objects.py` | 公钥、主密钥、压缩用户钥和签名的严格规范对象 |
| `paper_backend.py` | setup/key_extract/sign/verify/load_signature 五方法 |
| `paper_validation.py`、`paper_audit.py` | 可复现生命周期、恶意输入和替换攻击记录 |
| `src/ibme/ibs/srgg_paper_service.py` | 持久固定发钥，默认 1 用户，独立锁等待预算 |

对应四个 `tests/test_srgg_paper_*.py` 文件及完整文件清单见 validation.json。
接口已独立实现；共享 registry/CLI、HIBE 配对和正式准入仍由统筹负责。

## 验证与复现

```bash
# From the repository root inside WSL; use the existing designated Sage env.
export PYTHONPATH=src:.
~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_audit --profile PARAM-I --output build/outputs/paper-PARAM-I.json
# Repeat with PARAM-II / PARAM-III; add --interpretation literal-density-width
# for notation sensitivity, or --production-random for OS entropy.
~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_profiles.py tests/test_srgg_paper_samplef.py tests/test_srgg_paper_backend.py tests/test_srgg_structured_geometry.py tests/test_srgg_algebra.py tests/test_srgg_wide_scalar.py
~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_service.py
```

实测 WSL2 Linux、Sage 10.9、Python 3.13.15；主机 Intel Core Ultra 7 255HX、20 核/20 逻辑处理器、约 31.36 GiB RAM。
身份 5 B、消息 32 B；SHAKE256 域分隔哈希按 ROM 建模。固定随机数仅用于测试；缺省后端使用 SecureRandom。
7 轮每轮为独立参数点的一次生命周期，不能解释成统计性能基准。下表为默认解释的固定测试运行；有并行作业，时间只作执行成本记录。

| 原参数组 | Setup 秒 | Extract 秒 | Sign 秒 | 恢复后 Sign 秒 | JSON 签名字节 | 成功替换数 |
|---|---:|---:|---:|---:|---:|---:|
| PARAM-I | 1.25 | 42.22 | 28.82 | 29.12 | 35423 | 0 |
| PARAM-II | 2.84 | 56.44 | 17.00 | 32.80 | 51144 | 1 |
| PARAM-III | 5.14 | 90.93 | 39.61 | 22.14 | 67219 | 1 |

PARAM-I 系统随机数完整程序最大 RSS 为 230512 KiB，约 225.1 MiB，见 [资源记录](PARAM-I-secure.resources.txt)；只对该次运行测量 peak RSS。
资源记录将本机 Sage 用户路径替换为 `~`。作者 C/gcc8.3/ANS 的尺寸、1000 次中位 cycles 仅作为 `published_inputs.author_report` 保存，未复现其性能或 ANS 格式。

测试覆盖同身份无熵复用、独立进程重启、双进程并发新身份、pending 后退出、4 类写入/提取失败、损坏状态保留、错误公钥/参数拒绝，以及四对象截断/追加/重复/额外字段、身份和消息绑定。
独立代数测试还对每组做 32 次随机伪造负控。零 witness 测试明确是数学 fixture，真实生命周期另见收据，不冒充密码学采样。
本地状态为可信明文文件；只验收了 WSL 进程/磁盘流程，没有硬断电、恶意回滚或跨 Windows/WSL 混写保证。

## 必须保留的攻击与误差结果

**PARAM-II、III 的真实签名发生同消息替换成功。** 在首个身份块对一个系数加/减 Q，`2A·Qe_i=0 mod 2Q`；当替换后仍在原 γ 内，原 challenge 仍通过。
默认 PARAM-I 本次没有合格候选，不代表此攻击不成立；density 解释三组本次均找到替换。
这排除当前实现的 native strong 主张；它不是 fresh-message 伪造，不能直接据此推翻论文的普通 EUF-CMA 结果。原定理到实现的其他条件仍须单独核验。
详见各收据 `native_strong_probe`，不发布实际签名或私钥。

有限采样证书保留真实保守界：默认 PARAM-I/II 的 SampleF 总界约 `2^-15`；PARAM-III 主扰动约 `2^-14`，签名扰动当前公开界为 **1**。
后一数值含通用数值界退化，不能写成已证明高精度采样。density 解释三组总界均为 **1**。这不是测得的分布距离，也不是失败概率；当前界不足以认证论文 ε 或高查询预算。
ζζ*=2 与字面 factor1、HNF/FS 分布和 QROM 适用性仍未闭合，未因功能通过而删除。
初轮非中心余数导致签名形状失败的两份收据也保留；不能把该实现偏差当作原论文参数无效的证明。

统一声明：`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`。
Kyber/ML-KEM/NIST 仅为长期对标目标。功能与有限攻击不替代证明；完整安全归约、正式参数准入、原文 ANS/C 复现不在本批完成项内。
全部材料的 SHA-256 见 MANIFEST.json；English version: [README.md](README.md)。
