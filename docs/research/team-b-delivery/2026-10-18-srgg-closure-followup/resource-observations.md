# SRGG 原表资源观察与未测边界

基线为 `e38b2ea` 的七份最终真实运行回执，均在 [`2026-10-18-srgg-source-schur`](../2026-10-18-srgg-source-schur/)；环境见该目录的 [`environment.json`](../2026-10-18-srgg-source-schur/environment.json)。论文原数值固定为 `n=512,p=16383,b=31,w=2,q=961,Q=15744063,d=2/3/4`。表内时长是 Python `perf_counter` 对一轮调用的秒数，各实验曾并行，不能作为公平测速或与作者 C/ANS/1000 次中位数直接比较。表内字节数是一次真实对象的规范编码长度，随样本变化；不是固定上界。每轮身份 5 B、消息 32 B、一次根和一次发钥，含恢复后再签名。ROM 使用 `True`，固定伪随机源只用于测试；另有 PARAM-I 系统随机源。

| 原表 / Gaussian 解释 / 随机源 | 原表系数维数 master/sign | 公开密钥 / 用户密钥 / 签名编码 B | Setup / Extract / 首次 Sign s | Sign 尝试数 | 一次 Sign 的硬耗熵帽 B |
|---|---:|---:|---:|---:|---:|
| [I / 表头 / 测试源](../2026-10-18-srgg-source-schur/param-i-bounded-final-lifecycle.json) | 4096 / 4608 | 34522 / 84190 / 35334 | 0.574 / 2.347 / 4.505 | 4 | 363724224 |
| [I / 字面密度 / 测试源](../2026-10-18-srgg-source-schur/param-i-literal-bounded-final-lifecycle.json) | 4096 / 4608 | 34461 / 82813 / 33589 | 0.576 / 2.184 / 2.442 | 2 | 372943232 |
| [I / 表头 / 系统源](../2026-10-18-srgg-source-schur/param-i-secure-bounded-final-lifecycle.json) | 4096 / 4608 | 34520 / 84189 / 35418 | 0.624 / 2.375 / 2.644 | 3 | 363724224 |
| [II / 表头 / 测试源](../2026-10-18-srgg-source-schur/param-ii-bounded-final-lifecycle.json) | 6144 / 6656 | 76935 / 176721 / 51126 | 1.542 / 4.053 / 4.866 | 2 | 491366656 |
| [II / 字面密度 / 测试源](../2026-10-18-srgg-source-schur/param-ii-literal-bounded-final-lifecycle.json) | 6144 / 6656 | 76915 / 174653 / 48520 | 1.514 / 3.683 / 4.417 | 2 | 513032960 |
| [III / 表头 / 测试源](../2026-10-18-srgg-source-schur/param-iii-bounded-final-lifecycle.json) | 8192 / 8704 | 136604 / 303760 / 67112 | 2.989 / 6.399 / 7.477 | 2 | 619896512 |
| [III / 字面密度 / 测试源](../2026-10-18-srgg-source-schur/param-iii-literal-bounded-final-lifecycle.json) | 8192 / 8704 | 136519 / 301119 / 63783 | 2.952 / 5.877 / 6.737 | 2 | 646865792 |

耗熵帽是一次 `sign` 最多 64 次尝试的**运行硬限额**，包括 source-Schur 扰动与全部 `u` 抽样；它既不是实际耗熵测量，也不是发行服务终身上限。Setup 的正定重试、固定服务历史、样本外峰值内存和时限仍未给出闭合资源上界。现有 [`paper_resource_audit.py`](../../../../experiments/research/candidates/srgg/paper_resource_audit.py) 对原表与旧候选共 8 行进行公开构造/容量预检；其旧 joint 采样路径的有限 TV 数字不能转移给本表 source-Schur 路线。

原表 `31²` 环分量的实际 Hensel/CRT 构造见 [`ring-crt-31sq.json`](ring-crt-31sq.json)。其中 16 个 32 次因子和幂等元都已验证；所列系数范数只说明重构可能改变范数，不是 Ring-HNF、MSIS 或子域攻击的运算量。其它原表素因子的域分解、系数 CRT、HNF 形状和理想均匀矩阵可逆概率见前批 [`hardness-preflight-current.json`](../2026-10-18-srgg-source-schur/hardness-preflight-current.json)。真实采样根的条件化分布、非 3 因子的 CBD1 投影法则和实际攻击成本仍为未测/未证。

本记录不进行正式参数准入：`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`。功能运行和有限攻击不能替代安全证明。
