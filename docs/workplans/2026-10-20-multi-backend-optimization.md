# 多后端优化与完整流程消融执行计划

用户授权：继续第三项，先三代表，再补Luo／Falcon。本线程单独实施，不调用子智能体。开工基线`fe0b47d`，使用独立工作区；开工时77项CLI／CI目录回归通过，工作区初始干净。PR72及最新main的接收结果已随队友审查合并，当前任务仍为PR75的优化材料收口。

**目标：**交付能运行、能复核的优化实现和完整IB-ME对照，逐项列准备成本、重复使用收益、状态／内存代价及适用边界。保持既定算法、数值参数和wire；当前已完成配置跟随用户最新决定使用secure/true/true，归档实验保留其原字段。不改旧稿/PPT，不接管报告正文。

**设计：**先三代表，再Luo／Falcon。A和Falcon复用经过成功验证的公开证书，始终逐次验证消息签名；B复用同一不可变签名密钥的确定性SampleF准备计划，每次sample仍创建新熵预算；C提供显式、单发送者的进程内接收会话，实际执行一次Derive后复用其有效叶钥，原Lai后端继续无状态。Luo预计算NTT蝶形因子和置换，保持整数运算逐位相等。缓存均有界，不存放到wire，不缓存随机签名／扰动样本。

**技术：**Python／WSL指定Sage环境、原有LATTE／ML-DSA／Falcon／Sageloli原生桥、pytest。公开数据进入带日期research目录；真实密钥和日志只在持久私有目录，生成后先确认备份，再执行长测。

执行批次固定`b4b31d8`的同一wheel及原none/false/false快照；审查合并后代码与这批历史运行分别记账，不把原数据改写成新发布版实跑。已接收的修复包括备份排他创建、严格源码出处、元数据快照兼容和SRGG运行适配分离；研究源码保持冻结。

## 1. A：证书验证复用；同一实现后续覆盖Falcon

文件：`src/ibme/ibs/certified/backend.py`、`tests/test_cert_certificate_cache.py`。

- [x] 先写失败测试：相同证书、两条不同消息只验证证书一次，消息验证两次；身份／机构／用户公钥／证书变化必须重新验证；坏消息仍拒绝；False和异常不能缓存；容量与禁用受界限约束。
- [x] 新增有界正结果LRU和显式清空／配置入口。键是完整验证语句：算法、机构公钥、原certificate_message字节、证书字节。

```python
statement = (pk.params.base_algorithm, pk.authority_public,
             certificate_message(pk, identity, signature.user_public), signature.certificate)
# 缓存只保存engine.verify(*statement[1:])的字面True。
# 每次仍执行engine.verify(user_public, application_message(...), message_signature)。
```

- [x] portable缓存接线测试＋真实ML-DSA/Falcon契约与向量回归；实际完整系统记录native验证次数，不能用替身计为密码实验。

## 2. B：SRGG签名准备计划复用

文件：`experiments/research/candidates/srgg/paper_runtime.py`、`src/ibme/ibs/srgg/paper.py`、`tests/test_srgg_paper_plan_cache.py`；证据绑定的`paper_backend.py`与`paper_samplef.py`不再修改。

- [x] 先验证现有SampleF.sample每次独立创建AggregateByteSource，没有保存随机样本；准备计划只依赖固定签名钥和既定数值选项。
- [x] 失败测试先行：相同密钥只构造一次计划；不同密钥、配置、清空及容量淘汰不能误命中；计划构造异常不缓存。固定测试随机流下，复用和不复用的多个消息签名、熵消费逐字节相等。
- [x] 独立运行适配以`_build_sign_plan`调用原构造，有限LRU保存`(密钥原对象, 配置快照, plan)`；保留关闭入口作为同源码消融。密钥为已校验冻结对象，不读取跨原语私有矩阵。
- [x] 跑现有SRGG论文后端／SampleF／装配回归，保留原采样器、标准差、范数、挑战及中止条件。

## 3. C：显式接收会话

文件：`src/ibme/protocol/prepared.py`、`tests/test_prepared_receiver.py`、相关契约说明。

- [x] 失败测试：准备时真实调用一次derive；重复解密继续走原BYTEAUTH／Hybrid／IBS检查；错身份、错根、坏wire、有效外层无效内层拒绝；关闭后不自动重新派生。
- [x] `prepare_receiver(proto, public, receiver, sender_id, rng=None)`先核验公钥绑定，再真实derive并核验叶钥路径，构建仅固定该接收者和发送者的会话。
- [x] 会话将原协议的derive调用替换为已准备的不透明叶钥，解密其余步骤原样执行；原`LaiHIBE`、默认装配和CLI恢复继续按原语义工作。会话不提供持久化，不算新增HIBE／IBS算法。
- [x] 公开记录首次准备时间、叶钥额外字节、缓存命中、实际derive次数及总成本；不能把复用后的成本称为原无状态算法每次解密成本。

## 4. Luo：确定性NTT准备

文件：`src/ibme/ibs/luo_module_math.py`、`tests/test_luo_module_math.py`。

- [x] 先写失败的准备／重复运算测试，以及与旧蝶形算法、schoolbook的差分，覆盖零值、边界整数和现有宽模数。
- [x] 固定参数构造时准备公开蝶形因子和bit reversal；每次NTT直接使用。`multiply/matvec`接口及整数结果不改，准备时间和内存分列。
- [x] 原Luo模块数学、签名、编码及完整组合回归通过后，才执行目标配置消融。

## 5. 完整流程实测与交付

文件：`experiments/research/backend_optimization_probe.py`、`tests/test_backend_optimization_probe.py`、`docs/research/2026-10-20-multi-backend-optimization/`、CI登记、当前状态对应行。

- [x] 为驱动先测试：配置／输入／模式必须明确，失败或超时不能变成功，实际provider和源码不匹配即拒绝；公开结果不含密钥或日志原文。
- [x] A/B及Luo/Falcon沿用64 B身份、32 B消息，同机、同安装、相同Suite，至少3个独立CSPRNG根，顺序交错比较优化关闭／开启的完整加解密。每条消息使用新签名及新OTS，记录字节、熵、次数、准备时间、RSS、原始点及统计。
- [x] C为明确单根功能／摊销研究：真实生成与持久备份；原无状态路径和准备会话均实际执行，记录至少2次原解密、会话准备及至少3次复用解密。每个慢操作有显式上限，失败保留原件且不抽根重试。不把该批当作三根公平基准。
- [x] 每项有完整诚实往返、严格wire／签名负例及跨配置／身份绑定；有效外层内层拒绝须实际到达IBS验证。计时包括实际完整协议和编解码，不把裸内核收益填入完整系统列。
- [x] 从公开原始点生成表／图及只读校验入口。正收益、无明显收益及回退分别结论；不以既有部署收益冒充新的算法改造，也不要求所有阶段都更快。
- [x] 定向回归、实际收据校验、`git diff --check`后逐项提交；推送队长仓库独立PR并附真实链接。旧收据和其他人的PR不改写。

独立审查采用本线程自审，不使用子智能体。第一轮任务以用户已确认的三代表→Luo/Falcon顺序执行；后续以实际热点和收益为依据，不启动参数扫描、暂停路线或额外证明。
