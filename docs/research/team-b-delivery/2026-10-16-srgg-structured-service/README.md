# SRGG 结构化五方法与持久固定发钥

2026-10-16。本批为已运行的结构化 SRGG 加上完整独立五方法、严格公共对象、显式描述符和持久服务。与 HIBE 选择无关；按用户最新决定只做本地 Git 提交，待全部独立工作完成后才统一 fork＋PR 推送。六项联合目标仍为 WIP。

## 交付行为

入口 `from ibme.ibs.srgg.structured import ...`，完整契约见 [srgg-structured-issuer.md](../../../specs/srgg-structured-issuer.md)。复用冻结的真实结构化算术、HNF、ζ、H1/H2 和 SampleF；数值 profile 固定 `query-bounded-deep`。四对象继承公共 IBS 基类，签名密钥绑定身份和公共摘要；canonical JSON 拒绝截断、追加、重复、未知字段、错误维度/上下文/范数。

同身份只发一次；已发缓存跨重启、合作进程并发请求保持原密钥。发钥前落盘 pending，最终落盘后返回；采样、保存、结束事务或中途退出不确定时阻断整个服务，不自动重抽。新建前计算覆盖最长身份及最坏系数的嵌套 hex 包络，超容量先拒绝，不取熵、不改目录。快照容量 2 MiB，默认2身份，1–64受具体包络限制。

独立 `backend_spec()` 交付参数类型、对象解码、格式/尺寸及环境检查；调用者显式选 `research-small` 或 `research-n512`。未修改旧后端或统筹的全局 registry、CLI、HIBE 配对。研究预设不代表安全参数。

## 实际生产随机生命周期

[n512.json](n512.json) 是一次真实根和服务的首次运行，不筛根、不重抽密钥。参数是已有研究点 `n512,d2,w8,p16383,b31,r²64,Q13972913866395903,L16`；不是正式参数。

- 2个身份，长度13/11 B；各完成首次发钥、持久化和规范恢复。
- 共3个真实签名，消息32 B、65536 B、32 B；第三个在全新进程从状态恢复后签名。
- 同一进程和新进程的缓存命中禁止执行 Setup/Extract；验签对象禁止取熵。
- 诚实、错误身份、等长错误消息、规范签名加载及随机伪造检查均得到收据中的预期结果。
- 保守快照包络1,817,342 B，实际最终状态1,547,490 B；公钥282,483 B，签名135,135/135,209 B。随机值决定实际字节长度。
- 总92.159 s；Setup含持久化1.158 s，两个Extract含持久化15.978/15.962 s，两个Sign19.154/16.472 s；新进程启动/恢复/签名合计21.859 s。不是纯算法基准或稳定性能分布。
- 主进程耗熵30,243,940 B，新进程5,897,794 B；各进程的256 MiB审计总熵上限没有概率认证，不能把未触发写成中止概率零。

环境：Intel Core Ultra 7 255HX，WSL Ubuntu-24.04/Sage10.9/Python3.13.15；WSL可见20逻辑CPU，未固定频率/亲和性。Linux `ru_maxrss` 父/子高水位报告各247,876 KiB；这是进程高水位口径，不是两者同时内存之和。[small.json](small.json) 为另一个真实小维服务样例。JSON的 source hashes 绑定所列11份文件，清单另绑定选定关键依赖与冻结基础证书；不称为全系统依赖闭包。

服务状态只存在于专用临时目录，结束后清除；报告未输出私钥、签名、Gaussian样本或异常文本。它使用本地可信明文状态、合作写者模型，无恶意回滚保护或快照认证。

## 测试和负面证据

指定 Sage 的五方法、服务与描述符测试 **81 passed，0 failed/errors/skipped**。覆盖真实采样、两类并发、真实子进程崩溃、pending/final/finish失败、无熵缓存、错误公钥/参数、符号/硬链接、最长身份/消息及严格对象。独立描述符审查另跑7项，与81项重叠，不相加。准确命令和公开收据见 [validation.json](validation.json)。

小点 `n8,d1,w3` 有公开零响应伪造，且可在两个身份下接受。新增回归明确保留反例，不修改验证语义掩盖。低熵研究点的随机攻击/哈希碰撞也可能导致审计的负面检查失败；接口工程测试与这种安全结果分开记录。早期描述符测试有1项失败（6通过），其断言将整个随机小点审计视为必须通过；后改为只断言实际工程生命周期，保留审计的每项攻击结果。初次失败收据和说明保留，不用后续成功收据覆盖。

失败攻击测试不构成安全证明。n512的困难性对照见 [hardness](../2026-10-16-srgg-hardness/README.md)，不能支持Kyber/ML-KEM、NIST正式强度；更大候选尚需新资源、结构攻击与证明验收。连续采样误差、HNF发钥分布和原生strong/QROM归约分别核验，不能从固定服务通过推导这些结论。

## 复现

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q \
  tests/test_srgg_structured_backend.py tests/test_srgg_structured_service.py \
  tests/test_srgg_structured_registration.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.srgg_structured_service_audit \
  --degree 512 --output build/outputs/srgg-structured-service-new/n512.json
```

输出路径须不存在，避免覆盖收据。该命令会新取真实熵；若失败，报告实际阶段，不自动换根重试。每次的字节、时间和随机输出可不同。

```text
python experiments/research/srgg_structured_service_delivery_check.py
python -O experiments/research/srgg_structured_service_delivery_check.py
```

只读检查 [MANIFEST.json](MANIFEST.json) 与冻结classical-ROM/基础证据，不重跑测试。JSON逐字节复制；公开JUnit仅移除hostname并统一LF，原始收据留在ignored build目录。

```text
security_claim=none
backend_admitted=false
parameters_are_formal=false
nist_security_category=null
```

未闭合：独立安全归约/量子预言机、实际全局cap和基础设施异常的实验模型、结构化困难性与正式参数、更大候选执行器。共享接入和HIBE组合仍由统筹负责。
