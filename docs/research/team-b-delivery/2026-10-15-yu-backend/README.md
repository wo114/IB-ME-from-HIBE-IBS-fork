# Yu 本轮交付：代码能独立使用，安全参数仍未准入

日期：2026-10-15。基于最新上游 `8ba7ebf`；实现提交 `bbb8e47f66cd366d228917eec9c4452d622367ef`。

## 先看结论

**这轮把 Yu 从“几段独立算法代码”补成了一个有统一调用方式、能固定发钥、保存和恢复的研究后端，并把电路、谱范数和参数条件逐项核验了。**

但“核验了条件”不等于“所有条件都成立”：当前仍是小参数、公开可伪造，默认只能处理1字节身份和1字节消息，还不能接入真实 Wang 组合。不要把本交付写成“Yu 已达到安全等级”或“已证明绝对无bug”。

## 1. 这次具体做了什么

| 部分 | 交付内容 |
|---|---|
| 电路 | 核对 BPR 数值计算与密钥输入 NAND 电路；继续检查公私同态求值与匹配电路；记录门数、深度和资源限制。 |
| 谱范数 | 新增不用浮点近似的整数上下界、当前 NAND 递推的保守通用界，并用精确特征值交叉核验。没有冒充原论文较紧的 Lemma7 界。 |
| 参数 | 整理原文条件、实际配置、宽度充分门槛、失败与未准入项。保留原 tiny 配置，新的字节配置单独命名。 |
| 公共后端 | 提供初始化、发钥、签名、验签、签名加载五方法；公钥、主密钥、用户密钥和签名均有严格规范对象。 |
| 固定服务 | 相同身份只发同一把密钥；支持保存、重开进程恢复、跨进程锁、先保存再返回，以及中断/写盘失败后阻止自动重试。签名仍每次使用新随机数。 |
| 修复 | 统一畸形身份恢复错误；阻止后台线程进入会崩溃的 Sage 格运算；修复可写参数副本和特殊字节子类两项独立审查发现。 |

没有重写或放宽格采样器；没有偷偷哈希长输入、删掉攻击反例或伪造组合成功。三条并行支线分别负责条件、服务和独立代码审查，最后由主线汇总复测。

## 2. 实际跑到了什么程度

| 检查 | 本轮结果 | 说明 |
|---|---|---|
| 最终完整 Yu 测试 | **550 passed，0 failed，0 skipped** | 10个测试文件，101.39秒；16条旧JUnit格式警告不是跳过。 |
| 公共框架/CI目录/文件锁回归 | **57 passed** | 22.25秒；与上面的部分检查重叠，不相加充当独立实验次数。 |
| 电路核验 | 15组、45次数值对照、14次同态检查 | 合成公开样例，不是15次真实初始化。 |
| 修复版系统随机整链 | **3/3根完成，6个身份，18次签验** | 另有6次恢复后新签名；完整参数和每次记录见JSON。 |
| 早期系统随机批次 | **2/3根完成，1次Setup采样中止** | 12次签验、4次恢复签名；失败保留。修复前后采样器/参数未改，不能把后批3/3说成修好了随机中止率。 |
| 隔离安装 | **15项检查通过，67个加载源文件核对** | 离开仓库目录，从本地wheel安装到临时目录；无联网安装依赖，没有依赖源码目录“碰巧可用”。 |
| 独立审查返工 | 2项P2已复核关闭 | 新增7项回归；审查员16项定向复核通过。范围和复现见[审查记录](REVIEW.md)。 |

成功测试夹具中，有些使用测试固定随机源或固定公开矩阵秩前缀；不能当成无条件Setup分布实验。上表单列的系统随机批次不固定前缀、不隐式重试，发生中止就记失败。旧版和修复版结果分开，不把每轮重跑累加成一套安全证据。

### 小参数尺寸与诊断耗时

修复版原始记录中：公钥32,275 B；用户密钥32,969–32,980 B；保存两个身份后的主状态34,250–34,258 B；签名247–253 B。以上是本次规范JSON线格式，整数位数会影响长度，描述符的保守最大签名长度不是这个实测范围。

本机 Intel Core Ultra 7 255HX，WSL2、Sage10.9、Python3.13.15；未请求专门算法硬件加速。6次发钥中位数约4.157秒，18次签名约0.157秒，18次验签约0.089秒。计时包含相应调用中的电路/检查，不包含进程启动；当时有其它核验并行运行，**只是排障记录，不是隔离性能基线，更不能用于安全方案优劣排名**。全部样本在[生命周期记录](lifecycle.json)。

## 3. 当前明确不能写成什么

1. **不能写“不可伪造通过”。** 最终批次错误身份接受16/18、错误消息接受18/18；公开 `s=q·e₁` 伪造3/3成功。不是靠少量失败攻击来证明安全，这里反而明确展示小参数不安全。
2. **不能写“论文所有条件满足”。** 已给精确有限谱界，但密钥输入NC1族、Lemma7紧界与当前实现的对应、BPR正式困难参数、SIS归约beta和整体有限采样/中止预算仍未闭合。
3. **不能写“已经支持完整IB-ME”。** 默认非空身份最多1B，消息0–1B；可逆长度前缀变成40/40位，再加4位盐，共84位。Wang组合编码消息更长，接入预检会明确拒绝，不截断或哈希凑容量。
4. **不能写“生产服务已就绪”。** 私有状态是明文；要求本地单OS文件系统。格运算和私钥恢复要在进程主线程运行，并发用进程锁；不防恶意回滚、管理员改文件、NFS或混用Windows/WSL写入。

统一标志保持：`security_claim: none`、`backend_admitted: false`、`parameters_are_formal: false`。

## 4. 队友从哪里看、怎么接手

- 想先了解成果：看本README。
- 查论文与公式：[CONDITIONS.md](CONDITIONS.md)，区分原文事实、代码推导和有限实测。
- 开发调用与状态约定：[Yu专属契约](../../../specs/yu-ibs.md)。
- 公共代码：[src/ibme/ibs/yu](../../../../src/ibme/ibs/yu/)。独立原算法仍在[原Yu目录](../../../../experiments/research/candidates/yu/)。
- 统筹接手描述符：[registration.py](../../../../src/ibme/ibs/yu/registration.py)。本轮没有抢改默认registry、CLI、PROJECT_STATUS或其它成员原语；当前描述符只适合独立研究，不能把Wang容量拒绝改成放行。
- 查证据：[完整测试JSON](ci.json)、[JUnit](ci.xml)、[公共回归](common.xml)、[条件和电路数据](qualification.json)、[修复版真实整链](lifecycle.json)、[隔离安装](installed.json)、[保留的早期中止批次](historical-lifecycle-before-hardening.json)、[文件清单](MANIFEST.json)。

后续若选择Yu进入比较：需要优先明确满足目标容量的电路/参数及论文条件对应，再重跑真实路径和组合。基础定理以原文引用为主，但当前已识别的条件缺口不能靠“论文有证明”略过。此任务没有自动启动另一个算法。

## 5. 如何复跑

从仓库根目录，在指定WSL Sage环境执行（目录名换成新的，CI不覆盖旧收据）：

```sh
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m ci.run run yu2026 --output build/outputs/yu-recheck/ci
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_ci_catalog.py tests/test_assembly.py tests/test_cli_state_lock.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.yu.qualification --output build/outputs/yu-recheck/qualification.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python experiments/research/yu_backend_audit.py --attempts 3 --output build/outputs/yu-recheck/lifecycle.json
```

随机批次可能中止；脚本仍保存每次结果并返回非零退出码，不能删除失败后反复跑到全绿。若只核对已发布材料而不跑密码学实验：

```sh
python experiments/research/yu_delivery_check.py
```

隔离安装使用 `python -m pip wheel --no-deps --no-build-isolation --no-index . -w build/outputs/yu-wheel` 生成本地wheel，再用指定Sage Python运行 `experiments/research/yu_installed_audit.py --wheel <wheel文件> --output <新收据路径>`。不修改现有全局环境；临时私有状态自动清理。发布文件不含实际私钥、生产种子、发钥状态、实际签名或密文材料；单元测试中的固定公开测试随机串不是生产秘密。
