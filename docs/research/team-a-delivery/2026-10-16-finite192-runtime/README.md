# A1/A3：显式 finite192 配方的实际完整运行

2026-10-16；实现冻结 `73fe7c47f5fd1afdc5927d5c313b14dc3a0f83fc`（`feat(hibe): execute a versioned finite192 structured recipe`）。本批将有限误差配方接入真实结构化 H/G HIBE，并验收同根2×2、Luo完整组合和原状态隔离安装恢复。[修改文件清单](files-changed.txt)列出该实现及其交付证据。三条储备 GKR、ABB 标准模型、CHKP 标准模型保持暂缓。

此前 PR35 固定 head `584e436` 的远端46项检查成功、2项手动安全检查未执行，已合入 `91de0787a0a6eaacfd5d8912c6923fd61a0aa698`；本批基于该合入版本。PR34的要求修改记录保持独立，本批不依赖其未合并源码。

**本批完成了“新有限配方实际接入及验收”的缺口，没有得到正式安全参数。** n2仍不安全，`2^-131`是明确条件模型中的分布/正确性概率上界，不是LWE安全位数。高维q77/大R/精确运算/大对象域与完整安全映射继续WIP；没有增加算法或困难假设计数。

## 1. 版本、同组参数与旧版本兼容

新增公开参数类 `StructuredHIBEParams192` 和 `finite192_backend_spec()`，实际算法复用同一个 `StructuredMP12HIBE`。backend ID仍为 `mp12-structured-hg`，但descriptor版本明确为 `mp12-structured-hg-finite192-v2`；使用调用方显式注册表，默认registry/CLI仍选v1。接口与解析规范见[专属契约](../../../specs/first-suite-research.md#完整-hg-结构化变体的有限配方版本)。

| 同一完整配置 | 实际值 |
|---|---|
| n/q；根R平方宽；qα | 2 / 1099511627689（2^40−87）；16；4 |
| w/m；父采样/父公钥/叶维度 | 80 / 84；88 / 168 / 252 |
| gadget r²；根R公开平方范数界 | 800；5120 |
| 父输出平方宽；父R公开平方范数界 | 41600000；292864000000 |
| 叶输出平方宽 | 2342912000640000 |
| 身份/seed/树容量 | 每层86 B；32 B/256 bit；2接收者×2子地址 |
| 标量及根的实际配方 | tail192、Gaussian-abort192、mass320、precision384、uniform帽256 |
| 委派/叶实际配方 | epsilon192、扰动帽512，同一标量配方；实际采样所有坐标 |
| 实际 rounded-continuous 噪声 | tail192、mass320、precision384，radius门8192 |
| 条件解码/共享RO及KEM拒绝帽 | 单bit error160；两处既有帽仍128 |

q通过原实际根/gadget的Sage素性检查；完整参数、标量证书和计数在[公共账本](evidence/public-budget.json)。平方宽约定为 `exp(-pi*x²/s²)`，不能写成方差。

这不是把前批高维投影的整份配方当作已实现：本批明确保留共享RO/KEM的128次拒绝帽，选择接近2^40上端的q，并按实际拒绝率重新记账。测试将同一finite192版本换回旧q549755813911时，RO项重新超过128位概率目标，明确拒绝把epsilon192当作整个系统的概率结论。

v1的七个dataclass字段、默认参数和参数字节SHA256 `d567a43d2799de8086ab501e8d03306eff2b3153e9f587fab227bb964d6f870a` 保持不变。v2使用独立参数magic及完整配方记录；两种参数读取器交叉拒绝，通用对象读取器按版本分派，descriptor再验完整参数/类型。即使数值参数相同，v1不能接受v2对象；默认registry不能将v2 suite降级。隔离安装还逐项复算并确认旧v1完整概率账本不变。

## 2. 实际有限账本与准入边界

模型固定：1次根、2接收者、4叶，每叶256原像；160次父SampleD、1024次叶SampleD；2^20次封装、各2^20个H地址/G路径。实际噪声标量数为508×2^20；复用固定钥不增加SampleD。包含根均匀拒绝/有限Gaussian/范数、父叶耦合/范数、扰动中止、gadget与MP12卷积常数、实际噪声、KEM秘密与RO拒绝，以及条件解码。

本组累计上界落在 `(2^-132, 2^-131]`。单独解码项为 `2^-132`；不能把单项当作全系统上界。v2仅对最终概率项使用384位分母向外取整，正数不舍成0；独立边界测试覆盖极小概率与非二进制分数。增至2^32次封装的负控不再满足2^-128目标。默认v1仍保留原 `(2^-98,2^-97]` 结果，不被覆盖。

比较对象为同一计算型 `[I|Ahat]` 根、理想未截断Gaussian和理想RO随机流；假设包括独立均匀随机字节、正确有向舍入与已准入的精确路径。公共账本仍把“全部私有输入的算术/工作区失败”和“整个实现/协议失败上界”记为未知，不因一个实际树通过就填0。实际SHAKE/ROM、LWE困难性、匿名HIBE和固定服务安全映射、IBS/包装条件不由这份概率账本证明。

父的最坏随机请求预算5,164,058,554,880 B<2^44，单叶64,227,943,424,000 B<2^48；这是有限随机带上界，**不是预分配内存或实测熵量**。原所有数值/维度/Schur/对象/整树门保留。

## 3. 实际执行与原状态恢复

在规定WSL `~/miniconda3/envs/sage`、Sage10.9/Python3.13.14、Intel Core Ultra9 275HX、Linux6.18.33.2执行。完整命令/源码及结果散列见[audit.json](audit.json)。以下均为真实研究后端，未用mock替代；默认系统随机源和固定测试流分开记录。

| 本轮验收 | 结果与证据 |
|---|---|
| 冻结源码A严格专项 | **186 passed / 0 skipped**，135.40秒；[JUnit](evidence/strict-sage.xml)、[运行清单](evidence/strict-sage.json) |
| Windows相关目录/参数/发现回归 | **70 passed / 0 skipped**；[JUnit](evidence/portable.xml) |
| 系统随机完整IBME树 | **1个HIBE根、2接收者、4固定叶/1024真实原像**；32 B消息4条匹配、12条错配全部符合预期；[收据](evidence/system-tree.json) |
| 新进程恢复原树 | 4条原消息、全部已有用户钥复用、状态一致，**0熵/0新根/0新钥**；[收据](evidence/fresh-process-restore.json) |
| 原树复用 + Luo-C64B/compact + Hybrid/BYTEAUTH | 共同runner **1配置34项通过**，包含身份错配、对象/状态恢复、wire修改/截断/追加/重复、签名修改和内层认证拒绝；HIBE发钥熵为0；[完整结果](evidence/combination.json) |
| 仓库外 `python -I` 安装恢复 | **134个provider全部来自唯一安装根**；原树4条匹配恢复，0熵/0新钥/原磁盘状态不变；新账本复放、旧参数和旧账本完全一致、默认v1拒绝v2；[收据](evidence/installed.json) |

系统树与组合均通过公共协议和解码器，不读取原语内部矩阵补接口。系统阶段使用32 B消息、原身份Alice/Bob/Carol/Charlie（5/3/5/7 B），实际Hybrid内层两级各86 B；共同runner另按原规格测试10 B及空消息。Luo参数显式C64B，没有更改默认IBS。重复次数均为1，不把一个树的多次恢复当作多个新实例。

系统树约255.56秒、进程峰值346136 KiB（约338 MiB）；测得13,000,483次系统随机API调用、232,921,189 B，只记录计数和字节数，没有保存随机带。系统树与专项回归曾并行，计时包含发钥、协议/序列化、验证和保存；这些数值是执行诊断，不作与v1/ABB/其它算法的公平性能比较。

开发期Windows一次子进程发现测试因缺少继承的源码路径失败（69通过/1失败），[原JUnit诊断](evidence/portable-environment-first.xml)保留；设置显式 `PYTHONPATH=src;.` 后同判据70通过，未改测试。公开收据只规整换行和行末空白，原文件路径及字节散列另列在audit中。开发期Sage184项通过后增加两项边界测试，最终固定源码186项全部通过；计数交叠不相加。系统树第一次生成即通过，没有失败地址重抽。

## 4. 显式接入与重放

```python
from ibme.assembly import BackendRegistry, default_registry, make_suite, build_runtime
from ibme.hibe.mp12_structured import finite192_backend_spec
from ibme.ibs.luo_module_profiles import c64b_params

registry = BackendRegistry((finite192_backend_spec(),
                            default_registry().get("ibs", "luo-module")))
config = make_suite(hibe="mp12-structured-hg", ibs="luo-module",
    ibs_params=c64b_params(), transport="hybrid", protocol="byteauth-v1",
    signature_format="compact", registry=registry)
runtime = build_runtime(config, registry=registry)
```

用新目录运行一次系统实例，随后只恢复同一目录；`<source-sha>`取当前已提交版本：

```sh
export PYTHONPATH="$PWD/src:$PWD"
export OMP_NUM_THREADS=4 OPENBLAS_NUM_THREADS=1
~/miniconda3/envs/sage/bin/python -m experiments.research.structured_finite192_probe \
  --private-directory test-results/my-finite192/private \
  --source-commit <source-sha> --output test-results/my-finite192/system.json
~/miniconda3/envs/sage/bin/python -m experiments.research.structured_finite192_probe \
  --private-directory test-results/my-finite192/private --restore-only \
  --source-commit <source-sha> --output test-results/my-finite192/restore.json
~/miniconda3/envs/sage/bin/python -m experiments.research.structured_finite192_probe \
  --private-directory test-results/my-finite192/private --matrix \
  --source-commit <source-sha> --output test-results/my-finite192/combination.json
```

生成只接受新的ignored `test-results`子目录；已存在/失败目录不重建。公开收据与私有状态目录分开；本次Git交付只含白名单公开收据，主钥、用户钥、原像、随机带和原始状态不入库。隔离安装从原私有实例只读恢复，复算账本而不生成第二棵树。

本轮仅跨到A专项测试清单和专属契约，原公共框架probe增加可选显式registry/cases入口以复用已有验收；默认调用行为不变。没有改公共协议、默认注册器/CLI、B/C原语、wire资源上限或三条储备路线。

## 5. A剩余工作

新配方的实际运行、版本绑定、失败状态、恢复和单一真实组合已交；默认v1及其它配对不会自动升级。正式高维参数/大R与精确算术/大对象编码、192配方在困难维度的可运行域、计算根及匿名/固定服务模型映射、同安全目标的完整IBME比较/消融仍未闭合。A整体仍为 **WIP**；本批0项新增安全证明，保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。
