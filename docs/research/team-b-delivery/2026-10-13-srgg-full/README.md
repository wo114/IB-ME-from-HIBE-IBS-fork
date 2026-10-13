# 完整 SRGG 研究 IBS 交付

本批在 `3b50a40` 上完成SRGG的Setup、Extract、Sign、Verify、规范签名加载、固定身份缓存与恢复。完整真实运行不再只停留于扰动或gadget组件。代码在 [SRGG目录](../../../../experiments/research/candidates/srgg/)，冻结五方法由 `backend.Backend` 提供；原语对象继承公共IBS基类，可直接接公共协议。当前是 **ζ一致解释的完整研究实现**，`security_claim=none`、`backend_admitted=false`，不授予正式安全等级。

## 已实现范围

| 文件 | 实现 |
|---|---|
| `config.py` | 完整参数/资源快照；Q>2γ、整类根/用户谱充分条件、精度与票据关系 |
| `hashing.py` | 32 B公开seed的XOF；H(ID)无偏映射到R_Q^d；Hbar(w,message)二进制多项式挑战；域分隔/全公钥绑定 |
| `full_sampling.py` | 数值SampleF：真正连续normal近似+固定r离散Gaussian随机舍入；多项式块Schur条件采样和独立标量Gaussian |
| `runtime.py` | 原文SampleP特殊下块先离散采样，上块调用SampleF；真gadget/尾密钥；签名承诺、u半整数中心和响应 |
| `objects.py` | 公共seed/B、秘密CBD1 R、用户tail key、(z,c)；规范JSON/全参数/范数绑定；issued/pending/failed缓存快照 |
| `backend.py` | 五方法；唯一已发身份复用，失败地址保留；原文范数重试有帽，其他采样/形状错误立即退出 |
| `full_audit.py` | 真实完整生命周期、恢复、实际wire和计时公开白名单，不输出秘密状态/几何 |

没有重写公共协议、HIBE或已有Luo/Wang。默认registry/公开安装接入属于统筹，本批交 [独立登记提案](registration-proposal.json)，未冒称默认CLI已登记。

## 原文与明确解释

锚定 [12页缓存原文](../../../../papers/2025_efficient_ibs_jia.pdf)，SHA256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`：PDF7的Algorithms1–6、PDF8的Algorithms7–8、PDF6 Table3、PDF4 Definition3。

- Setup：公开seed生成Ahat，秘密R按CBD1抽样，生成B=F−[I|Ahat]R modQ。公开根宽度覆盖全部允许CBD1类；实际主扰动仍检查精确正定/shifted floor。
- Extract：SampleP真实相关扰动，SampleGadgetF真实随机原像，保存尾向量；Sign前按HNF恢复第一块。相同身份复用已发key，缓存随主秘密严格恢复；failed/pending地址不自动重抽。
- SampleF：从独立固定长度均匀票据经Box–Muller产生normal近似，精确LDL导出高精度Cholesky，物理协方差为 `(shape−r²I)/(2π)`；连续位移加到原始精确QQ中心，再按固定r做真实离散Gaussian随机舍入。模块Schur叶和整条均值/字节/有理数路径先准入，再消费熵。
- Sign：重建y，barA=[2A|Qj−2H(ID)] mod2Q；新p产生w，c=Hbar(w,message)，u中心为−c/ζ=−cζ*/2，z=p+[y;1](ζu+c)。范数超界按Algorithm7重新执行整个尝试，最多16次；内部随机源/采样中止不补抽。
- Verify：严格检查shape/context/范数，重构barA z−Qjc mod2Q，核挑战相等。遵循原文允许零响应，测试保留小挑战公开固定点伪造。

三处文字差异没有隐藏：主sigma²按Table3/Algorithm3/SampleZ取b²r²；SampleF图的输入f而根号写d，按f解释；ζζ*=2使ζu+c形状为2r²，故本版本签名扰动减去2r²TTᵀ，显式命名“ζ一致研究解释”，不同于Table3字面factor1，**不宣称已取得作者勘误或定理自动适用**。

有限票据格点与实数精度尚无整个连续stage的TV证书。已有gadget误差与舍入内核预算只属于相应组件，不能写为整个IBS/QROM证明。HNF重建后的key分布、底层强不可伪造前提和正式参数映射仍未准入。

## 参数与真实收据

| 项目 | 本批研究档 |
|---|---:|
| n / d / p / b / w | 8 / 1 / 257 / 31 / 3 |
| q / Q | 29791 / 7656287 |
| master两平方宽度 / r² | 2^23 / 4 |
| 用户完整向量norm²门 | 2^29 |
| signature两平方宽度 / γ² | 2^37 / 6597069766656 |
| exact Q²>4γ² | 通过 |
| 高精度 / normal票据 | 192 bit / 128 bit |
| 身份/消息/用户容量 | 256 B / 4096 B / 16 identities |

[新真实32次生命周期](audit.json)使用系统随机源：32/32签验、恢复后签验、恢复缓存同key均通过。实际公钥785 B、含一个已发用户的主秘密5377 B、用户key1796 B、签名465–491 B；这是本次canonical JSON研究wire，没有使用ANS，也没有套用作者C性能或安全等级。

n=8挑战仅8bit，即使Q>2γ也存在廉价公开固定点伪造；独立测试实际构造不持有key的零响应有效签名。该档是完整算法调试配置，不能用于参赛安全实例或公平安全参数排名。所有秘密状态均为可信本地明文，不提供加密存储、防回滚、线程/跨进程唯一发钥事务。

## 验证与使用

```bash
source ~/miniconda3/etc/profile.d/conda.sh
conda activate sage
PYTHONPATH=src python -m experiments.research.candidates.srgg.full_audit --repetitions 32 --output /tmp/srgg-full-public-audit.json
```

单体调用：

```python
from experiments.research.candidates.srgg.backend import Backend, Config
b = Backend()
pk, master = b.setup(Config())
key = b.key_extract(master, b"Alice")
sig = b.sign(key, b"message")
assert b.verify(pk, b"Alice", b"message", b.load_signature(pk, sig.to_bytes()))
```

精确命令、源码指纹、测试结果与失败修复见 [validation.json](validation.json)。Windows跳过真实Sage模块不计为执行；完整链与采样均在规定Sage环境实际运行。公共协议测试用mock HIBE，只证明接线与四种匹配，未冒称真实CHKP+SRGG配对。

独立复核后修正Config精度关系与范数重试边界；数值采样器另通过28项专属检查，覆盖连续矩/相关性、精确均值平移、正定/资源预检、typed memoryview、中止和秘密输出白名单。默认安装、全部真实HIBE配对、作者n512档/优化、数值总误差与安全条件核验是后续工作。

最终相关回归：Sage **167 passed / 0 skipped**；Windows **53 passed / 11 skipped**（真实Sage采样/生命周期在Sage已执行，交叠不相加）。源代码提交 `fc66882`，具体文件列表和指纹见validation.json。
