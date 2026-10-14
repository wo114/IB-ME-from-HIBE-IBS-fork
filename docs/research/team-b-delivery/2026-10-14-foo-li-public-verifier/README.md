# Foo–Li 独立公钥验签补齐

来源：Foo–Li，*Tightly Secure Lattice Identity-Based Signature in the Quantum Random Oracle Model*，ACISP 2023 作者接受稿，仓库 `papers/2023_tightly_secure_ibs_foo.pdf`，§3 Figure 2。PDF SHA-256：`845855b9b39fdcbbe61831d9d1c431dc8d898b5a6244863ff87b23171b1e45b8`。

## 本批做了什么

原研究代码已经实现 Setup、Ext、Sig、Ver 的数学流程，但 `Ver` 只能作为持有主秘密的 `ResearchSession` 方法调用。Figure 2 的 Ver 输入是公开主密钥、身份、消息和签名。本批增加 `experiments/research/foo_li_public_verifier.py` 的 `PublicVerifier`，构造时只传公开配置、epoch、主公钥矩阵和公开哈希源；不持有主陷门、主种子或用户签名种子。公开矩阵要求规范模 `q` 表示并复制为不可变对象。

签发方和公开验签方复用同一公开上下文、公开哈希与验签方程。保留原始算法语义：签名只采样一次，Ver 检查完整有符号整数范数及模 `q` 方程，没有添加拒零或自动重试。新增测试核对跨四条消息的真签名、错误输入的两路径一致性、公开哈希逐项相等、非规范公钥拒绝和公开哈希中止。

## 实际核验

在规定的 WSL `~/miniconda3/envs/sage` 环境，仓库根目录执行：

```text
~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_foo_li_*.py
```

修改前：`161 passed in 63.02s`；修改后：`164 passed in 74.25s`，0 failed、0 skipped。测试使用 `q=3,n=1,m_bar=1` 的公开教学配置、固定测试随机源及 SHAKE 候选，属于核心代码功能检查。用例中的身份 Alice/Bob，消息为空串及 1–7 字节样本；无性能基准或正式安全参数。

## 保留的界限

`security_claim: none`；`backend_admitted: false`；`parameters_are_formal: false`。公钥验签独立可调用，不等于 Foo–Li 论文的安全归约已闭合。固定身份多消息游戏转换、真实 SHAKE 与理想 ROM 的关系、正式 SIS 参数、共同 IBSBackend、Wang/HIBE 组合及部署用密钥存储都不在本批完成范围。测试通过不能证明安全性。
