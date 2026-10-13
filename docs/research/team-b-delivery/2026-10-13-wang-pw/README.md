# 队员 B Wang 与 Pan–Wagner 研究签名交付

本批从上游 PR #14 的 `87deec24f52c1c776a489566cf76f11d0d4a5aff` 开发，完成此前只有分析、没有完整签名代码的 Wang 基本 IBS + Pan–Wagner 转换。Setup、KeyExt、Sign、Verify、规范签名加载、固定已发身份密钥的多消息签名和跨进程恢复均实际执行。代码位于 [wang_pw](../../../../experiments/research/candidates/wang_pw/)。这是完整研究算法链，`security_claim=none`、`backend_admitted=false`，尚未进入默认 registry 或正式安全参数推荐。

本地克隆来自 `nomo258/IB-ME-from-HIBE-IBS`，其 `main` 为 `14f1163`；它是 `youzi258/IB-ME-from-HIBE-IBS` 的私有分叉。分叉无 PR，所审 PR 位于上游。开发分支为 `codex/b-ibs-wang-pw-2026-10-12`。PR #14 仅作为本地固定开发基础，本文不宣称已合并远端。

## 本批交付

| 文件 | 作用 |
|---|---|
| `params.py` | 独立完整参数快照、维度/素数/资源门与公开固定宽度 |
| `hashing.py` | PW 的两个盐哈希、Wang 两个内层哈希、长度前缀和无偏模 q 拒绝映射 |
| `engine.py` | 复用真实 MP12 生成、逐列秘密委派和完整扰动原像采样；无教学 fallback |
| `objects.py` / `codec.py` | 公钥/主密钥/用户密钥/签名，严格 canonical JSON、参数/身份/陷门关系校验、1 MiB 限额 |
| `backend.py` | 冻结 IBS 五方法；签名只使用已发 key 的身份与盐，异常不静默重抽 |
| `audit.py` | 真签名/恢复/公开伪造负控、实际 wire 尺寸和计时，输出白名单公开指标 |

独立复核发现两处 `memoryview` 按元素数误判字节数的问题，均在失败回归后修复：对象解析与随机源现在按 `nbytes` 检查；已释放视图按相应异常拒绝。主秘密和用户陷门从 `repr` 隐去；不公开真实采样器协方差、GS 几何或 SampleD 辅助 trace。

`key_extract` 遵循 PW KeyExt，可为同一原始身份发出另一份 key。发钥去重/事务由调用者或公共状态服务负责；重复 `sign` 和恢复保留同一份 key 的 `r` 与秘密，不重新 KeyExt。

## 原文与代码对应

| 原文位置 | 本次实现 |
|---|---|
| [Wang ePrint 2022/1718](https://eprint.iacr.org/2022/1718)，缓存 PDF 16–17 页 Figure 4、Lemma 2.5–2.7 | `setup` 生成 A 与秘密 G-trapdoor；`key_extract` 用均匀公开 B_x 形成 F=[A\|B_x]，由主秘密采样每列 G−B_x；`sign` 对 H2 采完整陪集高斯原像 |
| [PW ePrint 2021/970](https://eprint.iacr.org/2021/970)，缓存 PDF 12 页 Figure 5 | 身份盐 r 固定在用户 key；每次新取 s；J_id(id,r)、J_msg(M,s)；签名携带 r,s,z |
| [MP12](https://eprint.iacr.org/2011/501)，缓存 Algorithms 1、3、4 | 已有 `OnlineGaussianGenTrap` 和 `OnlineMP12SampleD`；独立 fresh RNG 逐列委派，保留公开宽度类与有限误差/资源门 |

引擎的 K 满足 `F[K;I]=G`；纸面 Wang R 满足 `F[-R;I]=G`，所以 R=−K。四个域独立；J_msg 不含身份，内层 H2 含内部身份。H1/H2 绑定规范公钥及完整参数，属于固定实例的输入编码约定。SHAKE 是实现候选，不能据此把真实随机预言机假设或固定服务条件归约写成已证明。

签名检查有符号整数 `z != 0`、`Fz=H2 mod q`、`||z||² <= d*s_sig²`。零向量、超范数、采样中止和质量超界明确抛出，不通过重复签名改变抽样分布。恢复检查全参数和秘密关系，但可信本地明文状态的数学一致性检查不等于加密存储、来源认证或防回滚。

## 参数与实测范围

| 项目 | 本批 debug 档 |
|---|---:|
| n / q / m_bar / w / m / d | 1 / 17 / 5 / 5 / 10 / 15 |
| 根生成宽度平方 / 根质量门 | 4 / 128 |
| 委派宽度平方 / 用户质量门 | 8127 / 406350 |
| 签名宽度平方 / 范数平方上限 | 25600113 / 384001695 |
| 身份 / 消息上限 | 256 B / 4096 B |
| 两个盐 | 各 32 B，未据此授予安全位数 |

[实际执行记录](audit.json)使用 WSL Sage、SecureRandom，32 个 25 B 消息，共用一个 5 B 身份的已发 key。32/32 签验通过，恢复后签验通过；公钥 400 B、主密钥 911 B、用户 key 1140 B、签名 340–353 B。这些是本次明文 JSON 研究对象的实际大小，不是原文压缩尺寸或正式参数下的性能比较。

本档不提供安全性：验签界远大于 q，**不持有签名密钥的公开线性求解伪造实际成功**；该负控保留在测试与 audit 中。根公钥近均匀性未获证，n=1/q=17 的消息哈希值域很小，错误消息可能碰撞接受；不将有限负向测试写成全面抗伪造保证。

audit 的 `sampler_classes` 只取公开零矩阵探针的白名单标量，按固定质量类报告 SampleD 的条件式有限误差。它不包含根生成/委派质量失败、零向量、验签范数中止等整体 IBS 失败账本，也不是整个 IBS 的安全证书。随机源独立均匀字节及正确舍入区间运算是采样界的前提，执行非常数时间。

## 复现

在 WSL 激活仓库规定环境后，从仓库根执行：

```bash
source ~/miniconda3/etc/profile.d/conda.sh
conda activate sage
PYTHONPATH=src python -m experiments.research.candidates.wang_pw.audit --repetitions 32 --output /tmp/wang-pw-public-audit.json
PYTHONPATH=src python -m pytest tests/test_wang_pw_reference.py
```

本机 Sage 没有安装 pytest。本次从已有 Windows pytest 复制其纯 Python 运行依赖到被忽略的 `.pytest-tmp-sage-deps/`，没有改变 conda 或用户安装；本机测试命令用 `PYTHONPATH=.pytest-tmp-sage-deps:src` 和 `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`。运行器不依赖 pytest。

本批精确测试、PR 审查与截图清单见 [validation.json](validation.json)、[PR 审查](pr-review.md)、[19 路线核对](algorithm-plan-check.md)。公共协议测试用 mock HIBE 验证五方法与四种匹配接线，不能记为真实 CHKP+Wang 完整组合。默认注册、公开安装、全就绪 HIBE 配对、正式有限参数及固定服务的安全映射由后继批次完成。

最终相关回归：Sage **233 passed / 0 skipped**；Windows **121 passed / 8 skipped**。两次运行有交叠，不相加为唯一用例数；8项跳过需要Sage，真实签名链在Sage已执行。首次混合Sage采集因缺cryptography失败，错误JUnit保留，随后按依赖分环境执行通过，没有删除断言或更改已安装环境。独立审查另核Wang14项、SRGG21项，均无skip。

[独立登记提案](registration-proposal.json)冻结factory/decoders、完整参数、格式、绑定和容量。该档有效签名的保守wire上限374 B；按每个合法坐标范数上界推导，实际32次签名为340–353 B。发钥cache由调用者负责，不能把固定已发key重复使用写成后端已实现唯一发钥事务。

SRGG 新组件与其严格边界单列于 [SRGG 下一实施入口](srgg-next-step.md)。Sageloli SIS/RSIS、Yu PRF/委派/采样仍按路线计划推进，不能把本批组件或 Wang 的完成状态扩张给其它 IBS。
