# 同版本作品报告与演示材料

本交付完成赛前收口卡第三项：把[作品报告](../../IBME_作品报告.md)和[演示/答辩脚本](../../COMPETITION_DEMO_AND_DEFENSE.md)同步到当前实际完整系统。两份材料只使用[主展示参数卡](../2026-10-18-main-showcase-cards/README.md)和既有公开收据中的事实，不重新生成密钥、不把历史测试记为本批实验。

机器可读事实见 [materials.json](evidence/materials.json)，只读一致性核验见 [verify.py](evidence/verify.py)。事实文件冻结参数卡 SHA-256、主演示 Suite digest、输入与重复次数、完整系统时间/尺寸、安全标志、当前机器预检结果及尚未交付内容，并保存两份材料自身的 SHA-256。

## 1. 本次统一的展示口径

作品名称统一为“基于多类格困难假设的抗量子身份基匹配加密通用设计和优化实现”。当前主演示底座为 **LATTE-3 + BNN/ML-DSA-44 + Hybrid + BYTEAUTH**：

```text
card_id=latte3-bnn-mldsa44-hybrid-byteauth
hibe=latte / seed32 / latte3-cosac-fix-v1
ibs=cert-ml-dsa / ml-dsa-44 / IBME/CERTIBS/1
transport=hybrid
protocol=byteauth-v1
signature_format=reference
allow_mock=false
suite_digest=10a23d28bfdf9b2e18b140149561c43d62f2649feb78b72510d350b419233346
```

报告和讲稿均保留以下边界：三张现有完整系统卡共享同一个 LATTE HIBE，不是三种 HIBE；不同 security group 未证明具有相同具体安全目标，不作同安全等级排名；图形界面尚未交付，最终三组代表尚未锁定。

主演示的归档实验使用 64 B 接收者身份、64 B 发送者身份、32 B 消息，3 套独立系统状态、每套 3 对 warm 加解密。warm Encrypt/Decrypt 中位数为 0.211125/0.280116 s，完整外层密文为 142051—142146 B。恢复批次为 3 个新进程、9 次恢复后解密，读取 0 B 公共随机源。

## 2. 演示流程的改动

旧讲稿中的教学 ABB10/SIS、快速测试后端、旧测试计数和旧密文数字已经移除。新脚本按以下顺序执行：

1. 用明确选定的 LATTE/ML-DSA Suite 做无熵静态预检；
2. 只有两个 native engine 均可用时才新建真实状态；
3. 展示正确匹配、仅发送者错、仅接收者错、两者都错；
4. 展示密文翻转后 `BOTTOM` 和新进程恢复；
5. 原生依赖未就绪时改为哈希固定的公开收据重放，并明确“证据核验不是算法执行”。

当前电脑的实际预检返回退出码 2 和 `execution=not_executed`，两个阻塞分别是 LATTE bridge 与 ML-DSA native engine 未构建。材料没有写入这台电脑的解释器绝对路径；复现者必须选择当前机器实际安装的 Python/Sage，不能复制另一台电脑或仓库历史记录中的 Sage 路径。缺依赖不授权任何后端回退，也不记为算法失败。

## 3. 报告内容的改动

报告已从单一教学基线更新为当前通用系统初稿，内容包括：

- Wang 两层匿名 HIBE + IBS 基线、固定 `(rcv, phi)` 身份顺序；
- Hybrid 的 32 B seed、固定宽度身份、HKDF/AES-GCM 和 capsule AAD；
- BYTEAUTH 的完整外层字节认证及其条件边界；
- HIBE/IBS 独立配置、容量/依赖预检、严格 wire 和 v2 状态事务；
- LATTE-3 与 BNN/ML-DSA-44 的实际参数、源码版本和模型口径；
- ML-DSA、Falcon、Luo 三组完整系统的同边界时间、尺寸和恢复结果；
- 可归于项目的工程贡献与现成构造/算法的原创性边界；
- 当前预检阻塞、未完成 GUI、在途 HIBE、最终三代表和正式安全准入。

报告是同版本正文初稿，不等于赛方模板、图表、截图、PPT 和最终 PDF 已完成。

## 4. 比较生成与只读核验

在仓库根选择当前机器实际可用的 Python 3 解释器。第一条命令生成并写回 `comparison.json`，后两条命令只读核验既有证据：

```sh
<python> docs/research/2026-10-18-full-system-luo/evidence/compare.py
<python> docs/deliveries/2026-10-18-main-showcase-cards/evidence/verify.py
<python> docs/deliveries/2026-10-18-same-version-materials/evidence/verify.py
```

本次最终执行结果：统一比较为 passed，3 个 profiles、2340 个 provider occurrences；参数卡为 392 checks passed；材料校验为 164 checks passed。三个脚本均打开 0 个私有状态文件、生成 0 把密钥；不需要 Sage。

材料校验逐字段从 cards.json 重新计算 Suite digest，核对主演示全部中位数、密文/RSS、输入、次数、恢复熵和安全标志；再核对两份材料哈希、必需事实、旧口径禁词及所有本地 Markdown 链接。它不会替代原始密码学测试。

另用当前电脑实际可用的 Nix Sage 10.9（`DOT_SAGE` 指向临时缓存，不使用仓库历史 Sage 路径）执行：

```sh
<current-sage> -python -m pytest \
  tests/test_cli_selection.py \
  tests/test_combination_extension_contract.py \
  tests/test_ci_catalog.py -q
```

结果为 `105 passed in 176.57s`，无失败或跳过。主 Suite 的实际静态预检另行执行并得到预期的退出码 2、两个 native engine 阻塞及相同 Suite digest；它不计入实际组合运行。

## 5. 安全声明与未完成内容

```text
security_claim=none
backend_admitted=false
parameters_are_formal=false
security_proofs_produced=0
```

功能、拒绝、恢复、性能和材料一致性检查都不能证明 NTRU、RLWE、MLWE、MSIS、HIBE、IBS 或 IB-ME 安全。LATTE 身份匿名性继续作为用户确认的工程工作假设；论文 ROM 结果、BNN 条件、普通签名安全和包装条件分别引用，不声称 QROM、完整组合归约或 NIST 等级已经闭合。

本批未实现或未完成：图形界面、赛方模板终稿、最终三组代表、在途 HIBE 的接收与完整配对、正式参数准入、目标安全等级和当前电脑的两个原生引擎构建。
