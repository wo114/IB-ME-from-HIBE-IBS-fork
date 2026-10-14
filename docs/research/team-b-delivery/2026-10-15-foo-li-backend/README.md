# Foo–Li：从数学参考代码到可恢复的独立 IBS

论文：Ernest Foo、Qinyi Li，*Tightly Secure Lattice Identity-Based Signature in the Quantum Random Oracle Model*，ACISP 2023 接受稿，§3 Figure 2（PDF 第13页）。[本地原文](../../../../papers/2023_tightly_secure_ibs_foo.pdf)；DOI：`10.1007/978-3-031-35486-1_17`；SHA-256：`845855b9b39fdcbbe61831d9d1c431dc8d898b5a6244863ff87b23171b1e45b8`。

这次补齐的是 B 组任务书中的 Foo–Li 独立原语交付。原先已有四个数学算法和 PR26 的公钥验签，现在又补好了统一五方法、四类规范对象、固定发钥、异常处理、磁盘服务与恢复。队友可以直接调用这个后端，或根据随附描述符接到公共框架。

开发从上游 `8ba7ebf` 开始，包含 PR24—26。实现提交为 `46529e08a5bc390f477f1ba539122f4b24fcf44c`。原有四算法、采样器和公钥验签直接复用；没有重写已有密码数学。完整文件范围由 `MANIFEST.json` 固定。

## 现在能做什么

| 已交付内容 | 通俗解释 | 入口 |
|---|---|---|
| 五个公共方法 | 生成系统、发用户密钥、签名、公开验签、加载签名 | [backend.py](../../../../src/ibme/ibs/foo_li/backend.py) |
| 公钥、主秘密、用户私钥、签名对象 | 可以保存和读取；格式、参数、尺寸和可检查的数学关系不符合就拒绝 | [objects.py](../../../../src/ibme/ibs/foo_li/objects.py)、[keys.py](../../../../src/ibme/ibs/foo_li/keys.py) |
| 固定发钥 | 同一身份再次申请，拿到原来的密钥；不会偷偷换一套 | [service.py](../../../../src/ibme/ibs/foo_li/service.py) |
| 中断保护 | 发钥前落盘 pending；写完才返回。保存失败或进程中断后阻止自动重发 | 同上 |
| 独立签名和恢复 | 用户私钥不带系统主秘密；重启后能继续签名，同一消息的结果保持一致 | [原语测试](../../../../tests/test_foo_li_backend.py) |
| 统筹接入描述符 | 参数、工厂、三个密钥解码器、签名尺寸和缓存能力已交齐 | [registration.py](../../../../src/ibme/ibs/foo_li/registration.py) |

独立审查发现并修复两处资源检查问题：先限制分数字符串写法与位数，再解析 `epsilon0`；先按公开参数检查所有秘密矩阵形状、数值和发钥记录，再进行昂贵的矩阵恢复。对应测试要求非法输入不能到达后面的计算步骤。

## 实际验证和证据

- [CI 收据](ci-result.json)：本地执行全部 `tests/test_foo_li_*.py`，**294 项通过、0 失败、0 跳过**，约97.81秒；含原来的数学/证明契约检查和本次新增原语、磁盘服务测试。[逐项 JUnit 记录](junit.xml)。这不是尚未执行的远端 Actions 结果。
- [真实生命周期](lifecycle.json)：系统随机源生成3套主密钥、6个用户，36次真实签名/验签、36次恢复后重复签名，3次新进程恢复后签新消息。无采样替身。
- [独立安装收据](installed.json)：本地 wheel 装到临时目录，在仓库之外完成15项生命周期/恢复检查，53个已加载项目模块的来源均在安装目录，源码哈希与交付版一致。
- [审查与复核记录](REVIEW.md)：独立审查、修复位置、测试范围和保留边界。
- [完整实现契约](../../../specs/foo-li-ibs.md)：论文步骤、参数、失败、格式、状态与统筹接入说明。

以上批次有重叠，不能把不同批次测试数字相加成更多独立测试。新版本未重跑未改动的其它 IBS/HIBE 算法。

测试环境为 Intel Core Ultra 7 255HX、WSL Linux、指定 `~/miniconda3/envs/sage`，Python 3.13.15。原语回归用显式固定测试随机源，生命周期另用系统 CSPRNG；哈希使用现有有限 SHAKE 候选。性能样本含首次与已初始化路径，是小配置诊断；不作为同等安全强度的横向排名。原始分项耗时、重复次数、四分位数和完整参数都在生命周期 JSON。

默认研究配置 q=3,n=1,m_bar=1，主/用户质量界8/3402，s²=567、t²=214389。另有 n=2、用户质量界11340 的真实签验与恢复回归。系统随机批次身份均8字节，消息长度为0、5、3、32、256、4096字节；默认上限身份256字节、消息4096字节、16个身份。epoch 默认随机32字节。

该系统随机批次的公钥502字节、每把用户私钥631字节、完整签名104字节；主状态随已发用户数量和秘密整数的规范表示改变。**这些尺寸来自可公开攻破的小参数，不能写成“安全 Foo–Li 只需104字节签名”。**

## 怎么用

在 Sage 环境安装项目或把仓库 `src` 加入导入路径后：

```python
from ibme.ibs.foo_li import FooLiIBS, FooLiParams, PublicKey, SigningKey

ibs = FooLiIBS()                         # 默认系统随机源
pk, msk = ibs.setup(FooLiParams())        # 仅研究小配置
sk = ibs.key_extract(msk, b"Alice")
signature = ibs.sign(sk, b"message")
assert ibs.verify(pk, b"Alice", b"message", signature)
restored_pk = PublicKey.from_bytes(pk.to_bytes())
restored_sk = SigningKey.from_bytes(sk.to_bytes())
assert ibs.sign(restored_sk, b"message") == signature
```

需要磁盘服务时使用 `ibme.ibs.foo_li.service.FixedIssuer`：`initialize(params)` 建立新实例，`public_key()` 读取公钥，`key_extract(identity)` 固定发钥。目录必须专用、私有且父目录已存在；再次初始化不会覆盖旧状态。状态含主秘密和用户种子，不应放进 Git、公开材料或共享同步目录。发现 pending 时先审查私有状态，不能删标记自动重试。

可复核命令（仓库根目录，使用 WSL 指定环境）：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m ci.run run foo-li --output build/outputs/foo-li/ci
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.foo_li_backend_audit --output build/outputs/foo-li/lifecycle.json
```

安装检查：先在具备 setuptools 的构建环境执行 `python -m pip wheel --no-deps --no-build-isolation . -w build/outputs/foo-li/wheels`，再在 Sage 中执行：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.foo_li_installed_audit --wheel build/outputs/foo-li/wheels/ibme-0.1.0-py3-none-any.whl --output build/outputs/foo-li/installed.json
```

本机 Sage 缺少 wheel 构建所需的 setuptools，实际使用已有 Windows 构建运行时生成纯 Python wheel，再由 Sage 离线安装到临时 target；没有改动全局依赖。该检查不联网安装其它包。

## 剩余工作与报告口径

B3 的本轮代码交付是“具有完整公共方法和固定服务的 Foo–Li 研究原语”。默认 registry/CLI、与各真实 HIBE 的组合和公平评测由统筹接续；该 PR 提供描述符，尚不宣称这些组合已经执行。

当前仍为 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。q=3 下公开伪造、错身份/错消息和随机向量被接受的反例已实测并写入证据。它们说明此配置没有密码学强度，不能删掉反例或额外加标签来伪装原算法已经安全。正式 SIS 参数、采样总误差、原文安全引用的固定种子/查询条件及 Wang 组合前提仍待核验。

存储是明文且无恶意回滚防护；当前测试覆盖本地同 OS 文件系统的协作写入和进程故障，不提供跨 OS 硬断电保证。有限测试通过不能保证绝对无 bug，也不能替代安全证明。
