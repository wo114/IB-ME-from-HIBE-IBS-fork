# PR38：出版版 CHKP 目标的规定环境复核

2026-10-18。此PR在PR34／36／37处理结束的最后核对阶段新增，本轮一并审查。固定初版`1710792`已由作者整理到最新main的`58a50bd`，复核head为`2e1039247c2e28bae70351120575b2c782753e84`；新筛查器和测试字节相同，进度文档冲突已消除。[PR38](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/38)远端46项成功、2项预期手动安全检查未执行，已合入`cdf2797fe27c8bac9ce003ba753e7efff2bd9ef2`。接收范围为公开数值候选、原文差异说明及强制不准入字段，不是新增可运行HIBE或正式参数。

## 本轮独立核验

- 下载[作者网站2010稿](https://people.cs.rutgers.edu/~dc789/bonsai.pdf)，完整核对PDF20–21；字节SHA256为`87b5bff448f4e653bb7959a62c2b56c03ca495076678014b5dc8b7c90a90442f`。ROHIBE实际定义使用t*m、A0至A_(t−1)，Theorem5.3和模拟器匹配d*m及d−1个H前缀。仓库后期作者稿SHA256为`b1d8a2ae0e9d4e5c9145bbc6dc864090605c12a5b76149aa0684d62a8815d2ce`，完整检查其PDF22：定义为(t+1)m，同页Theorem5.2/模拟器却为d*m。该差异属实，现3m后端不能直接继承2m稿的定理。aid指adaptive identity；匿名填充需要另行对应。
- 实际检查新脚本和原共享投影：当前后端、codec和资源门未变；候选、比较模型、未闭合证明/资源门及正式准入字段分离。额外模拟H根/G向量、多bit、匿名padding和损失分别记账；Lemma2.4(4)的未实例化分配仍明确标为projection，不能据总数授正式准入。
- 规定WSL `~/miniconda3/envs/sage`，Sage10.9/Python3.13.14，Linux6.18.33.2，Core Ultra9 275HX，OMP4/OpenBLAS1：定向16 passed/0skip，完整A专项186 passed/0skip。原Nix证据保留，不冒充本轮环境。
- 新建干净Lattice Estimator checkout，固定`53da5982597709ba0fdf94ea37a84d822310fd84`。两角色×两成本模型×四类共16次比较全部有限返回；整个target对象及四份源码指纹与作者归档逐字段相同，环境字段分别记录。
- 未构造高维矩阵/根/钥或读取项目随机源。下载的论文及页面图仅用于本地阅读，不随公开Git交付；公开新收据不含私钥、随机带或签名样本。

| 新执行 | 结果 | 证据 |
|---|---|---|
| published target + 原target回归 | 16 passed、0 failures/errors/skips | [JUnit](evidence/target-wsl.xml) |
| a-structured-hg | 186 passed、0 failures/errors/skips | [清单](evidence/a-structured-hg.json)、[JUnit](evidence/a-structured-hg.xml) |
| 固定Estimator与完整数值账本 | 16有限比较，target与归档完全相同 | [公开报告](evidence/formal-target-wsl.json) |

上述测试有交叠，不相加。参数n6144、q667066744249733736124919（80 bit）、身份86 B/层、32 B seed及2^20声明查询/封装预算均为投影输入。概率指数131、根/密文扣声明损失241.788/230.105是明确比较模型中的数值；未声明NIST或实际安全位。单父R现JSON编码下界507343011840 B（约473 GiB）不是峰值RSS实测。研究后端仍只在原已验收的小参数域运行。

原始交付、全参数与原文定位见[目标说明](../../research/team-a-delivery/2026-10-17-chkp-published-target/README.md)，本轮准确命令、散列、head/合入状态及远端检查见[audit.json](audit.json)，[公开审查正文](evidence/review.md)同步保留。当前待办仍由[PROJECT_STATUS](../../PROJECT_STATUS.md)维护。

出版版2m+独立padding路线、RandBasis/等价秘密钥分布、原文有限常数、字面rounded-noise归约、全部私有输入算术/资源、完整攻击覆盖与Wang组合仍WIP。全部保持`none/false/false`，测试不替代证明；GKR、ABB标准模型、CHKP标准模型继续暂缓。
