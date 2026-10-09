# 已知漏洞回归与基础 CI

本检查保留老师的两层匿名 HIBE + IBS 通用构造，仅增加自动验收证据。
现有教学参数和密码后端未修复，`security_claim: none`。

2026-10-08 M1 补充：基础 CI 加入 `tests/test_luo_matrix_reference.py` 的 65 项数学研究检查，当前 CI 的普通批次为 247 passed、3 xfailed。下文 PR #5 的独立基础命令仍对应 182 passed、3 xfailed，两个批次不要相加。新参考使用小参数，包含“公开枚举伪造被接受”的负面对照；它不是已经通过安全准入的新 IBS 后端，三个旧漏洞目标仍未修复。

2026-10-09 M2-A 补充：当前 CI 再加入 83 项 Luo 适配器契约及 19 项参数/公开攻击检查，选择批次对应 **349 passed、3 xfailed**。完整本轮相关批次另包含旧 IBS/R1，为 412 passed、3 xfailed；批次有重叠。两个新小参数的等效主秘密都能由公钥枚举恢复，公开伪造被接受是明确的负面对照。四组手选大参数在公开矩阵变换后均出现约 2^11.680/2^10.601 的经典/量子 LWE 格攻击估算；固定 n=128 样本的公开 LLL 对照恢复了一列有界主秘密，但未恢复全部主密钥或测试完整伪造。这些都是研究风险筛查，不能替代全方案攻击证明或把参数称为安全。详情见 [M2-A](research/2026-10-09-m2/README.md)，三个旧漏洞的标记与目标未改变。

2026-10-09 M2-B1 补充：增加 19 项精确参数检查，当前 CI 选择为 **368 passed、3 xfailed**；本轮相关 Windows 431 passed、3 xfailed，WSL Luo 186 passed。M2-A 最低 LWE 数字来自 dual 区分攻击，不能写成完整主密钥恢复成本；独立 LLL 一列恢复仍有效。新矩阵筛查使用原文两种界中较大的界，并记录工具优化异常；模格 q、γ₃ 和 κ=64 只是研究参数，一般整除/NTT/Hint 条件与系数维数攻击估算不等于完整 MLWE/MSIS、IBS 或 QROM 证明。原来的三项漏洞仍未修复，详见 [M2-B1](research/2026-10-09-m2b/README.md)。

## 三个安全目标

| 编号 | 目标 | 当前教学实例 |
|---|---|---|
| LEGACY-IBS-01 | 不持有签名密钥的公开线性求解签名应被拒绝 | 被接受 |
| LEGACY-IBME-01 | 未获得发送者密钥的冒名密文应被拒绝 | 被接受 |
| LEGACY-CT-01 | 单字节密文修改应被完整性验收拒绝 | c1 低位修改后恢复原消息 |

`tests/test_known_security_gaps.py` 使用现有攻击求解器、真实 ABB10/SIS 教学后端和固定测试随机流。
协议伪造检查只给接收者发钥，不给被冒充发送者发钥。篡改检查先验证真实签名的合法密文可解密，
再改变完整序列化密文的最后一个字节，确认仍可规范加载且只改变最后一个 c1 系数的低位。
数据准备若异常或诚实解密失败，会报错，不能作为已知漏洞检查通过。

这些问题针对具体教学实例。原始 CPA 加密的解码容错本身不是论文通用定理被攻破；
但它不能满足项目额外的密文字节完整性目标。老师的强可认证性和 IBS 强不可伪造也不能等同。

## 普通基础检查

仓库根目录执行（Python 3.14、pytest 9.1.1）：

```text
python -m pip install -e . pytest==9.1.1
python -B -m pytest -p no:cacheprovider -ra --tb=short tests/test_encoding.py tests/test_lattice_core.py tests/test_prepared_hashing.py tests/test_known_security_gaps.py --junitxml=test-results/basic.xml
```

当前预期为 182 项通过、3 项 XFAIL。XFAIL 是已知安全目标失败，不计为安全通过，
也不计为普通跳过。GitHub Actions 输出明细和 JUnit XML，并在任务摘要说明验证范围。
JUnit 格式将 XFAIL 放在 skipped 元素中，并标记 `type="pytest.xfail"`；消费 XML 时应按这个类型与普通 skip 分开统计。
工作流使用只读权限和固定的官方 Action 提交，不调用 pull_request_target 或读取仓库秘密。

本批次显式选取无 Sage 依赖的基础模块，未执行完整协议套件、Sage 采样/参数模块或 Lean；
不把 CI 绿色状态宣传为满足全部赛题或证明密码安全。

## 严格安全验收

```text
python -B -m pytest -p no:cacheprovider --runxfail -ra --tb=short tests/test_known_security_gaps.py --junitxml=test-results/strict-security.xml
```

`--runxfail` 忽略预期失败标记。当前教学实例应出现三个断言失败并返回非零退出码。
也可手动运行 GitHub Actions 并选择 `strict_security=true`；严格步骤失败会使任务失败，
不使用 continue-on-error 隐藏它。

## 后续修复规则

- 标记使用 `strict=True` 和 `raises=AssertionError`；意外通过会造成 XPASS(strict) 并令检查失败。
- 仅在重新核对攻击、参数和真实后端后移除相应标记，不通过改写断言降低验收要求。
- 若旧教学后端保留为负面对照，新后端需要单独运行未标记的同等安全目标；不能把固定教学实例的 XFAIL 当作所有新后端的验收。
- 固定随机流只用于重放，有限成功样本不代替一般正确性、安全归约或失败概率证明。
- 全文证明、合法参数、采样和完整性包装仍按项目研究进度推进，本 PR 不代替这些工作。

## 本轮验证

先在无 XFAIL 的测试上复现三项断言失败，确认前置操作正常、攻击触及目标断言，
再加入严格标记。PR 交付记录应分别列出普通基础结果、严格安全结果和远程 CI 状态。

本地实测使用 Python 3.14.0a5、pytest 9.1.1，普通基础结果为 182 passed、3 xfailed（46.45 秒），
`--runxfail` 为 3 failed（45.00 秒，均为目标断言失败）。远程 CI 使用 setup-python 提供的 Python 3.14，
其结果应单独查看，不将本地解释器版本或耗时当作远程运行证据。
