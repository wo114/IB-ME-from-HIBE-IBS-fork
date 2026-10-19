# Lai C2 与四类 IBS 的真实组合运行

日期：2026-10-19。此前PR62公开的C2完整系统收据只有Luo模格一组。本目录记录新增的BNN-ML-DSA-44、BNN-Falcon-512、SRGG论文PARAM-I compact、Sageloli环版v3 PARAM-I四个组合，全部通过公共SuiteConfig／Hybrid／BYTEAUTH接口执行。

## 参数、输入与次数

HIBE使用显式`target-research` C2：`n=2048, q=274877976577, k=39, l=2, p=2, sigma=2, sigma_r=1`，`seed32`模式；来源为[已冻结C2参数及其限制](../team-c-delivery/2026-10-18-lai-target-parameters/C2-FREEZE.md)和[Lai契约](../../specs/lai-hibe.md)。本批未改动算法、采样器、身份编码或重新进行安全估计。

四组的应用消息均32 B，发送者、接收者及错误身份均64 B；Hybrid内层身份均86 B，内层载荷32 B。全部显式使用8 MiB Hybrid载荷预算与4 MiB胶囊预算，容纳Sageloli的大签名，默认预算保持原值。IBS完整数值和版本逐组保存在`evidence/trials.json`的`suite`中；分别沿用[BNN契约](../../specs/certified-ibs.md)、[SRGG论文参数交付](../2026-10-19-srgg-paper-latte/README.md)、[Sageloli v3契约](../../specs/sageloli-ring-ibs.md)。同一算法的参数或格式不增加算法计数。

使用一个新OS CSPRNG HIBE根和两个实际一级接收密钥，跨四个组合复用这些不透明公共接口对象；四组各有一个独立IBS根和发送密钥、一次完整加密。每组四个身份场景分别在新进程加载对象，并实际执行一次原Lai二级委派和完整解密。无叶密钥缓存、固定测试随机流或替代后端。复用根与一级密钥的范围明确记录，不能计作四个独立HIBE根或统计重复。

## 实测结果

| IBS | 完整密文 B | 完整发送钥 B | 加密 s | 诚实解密 s | 其中二级委派 s |
|---|---:|---:|---:|---:|---:|
| BNN-ML-DSA-44 | 1,333,849 | 8,050 | 88.55 | 425.41 | 393.71 |
| BNN-Falcon-512 | 1,329,934 | 4,195 | 91.09 | 425.76 | 394.11 |
| SRGG PARAM-I compact | 1,341,012 | 84,306 | 90.13 | 425.47 | 393.68 |
| Sageloli v3 PARAM-I | 4,555,436 | 144,089,680 | 98.97 | 424.98 | 393.04 |

表中密钥尺寸为公共协议对象`to_bytes()`的完整线格式；CLI v2状态文件还带Suite封装，比较时需区分这两种尺寸口径。

四组诚实恢复均匹配32 B；12次错误身份均返回BOTTOM且无明文输出，原文件不变；16个进程均实际完成一次Lai Derive。准备阶段88项加上身份场景16项，共104/104通过。

诚实解密测量阶段记录的本进程内核生命周期峰值为1.129–1.163 GiB。各组二级委派约占完整协议解密的93%，是本次单次实测的主要耗时。

共享HIBE准备：shared-hibe-setup 2.13 s；shared-receiver-extract 31.17 s；shared-other-receiver-extract 31.00 s。两个完整接收钥线格式分别20,439,584 B、20,439,584 B。

每组准备阶段22项检查：公钥／主钥／发送钥恢复、密文规范往返、四种BYTEAUTH修改、截断／追加／重复／版本错误的加载与解密拒绝、外层拒绝未进入Derive，以及独立IBS签名的诚实验证、错误消息／身份、修改／随机签名。另有诚实、仅发送者错、仅接收者错、双方都错四次完整系统解密；每组26项，四组共104项观察。独立IBS负例另签了一条探针消息，不把它记作从密文取出的内层签名测试。

环境及逐阶段数据见收据：Intel Core Ultra 9 275HX、WSL2/Linux、Sage10.9、Python3.13、NumPy2.5.1；`OPENBLAS_NUM_THREADS=1, OMP_NUM_THREADS=1`，最多六个解密进程并发。原生ML-DSA／Falcon和Sageloli库复用此前构建，源码ABI与二进制摘要另存[依赖记录](evidence/native-context.json)。逐阶段内存是10 ms采样的本进程／进程树RSS下界，同时保留内核生命周期峰值；各进程峰值不能相加当作整机同时峰值。加解密计时分别记录，不能把共享根、单次并发试验排成独立根的公平速度排名。

## 核验与重放

执行逻辑冻结在`48f72292177a695a437154a91d315f76cb4e8d21`，实际加载源码按provider集合及文件SHA-256绑定；原始数据只有参数、时间、尺寸、内存、判断和源码指纹。私钥、原始密文、明文文件及失败诊断留在仓库外的新私有目录，不随交付发布。

- [公开运行收据](evidence/trials.json)
- [文件与实际provider集合清单](manifest.json)
- [只读校验器](verify.py)
- [真实运行脚本](../../../experiments/research/lai_c2_combinations.py)

只读检查可使用普通Python，无需Sage、原生库或私有状态：

```text
python -O docs/research/2026-10-19-lai-c2-combinations/verify.py
```

重放先按上述IBS契约构建原生引擎，并设置`IBME_CERTIFIED_SIGNATURE_BIN_DIR`、`IBME_CERTIFIED_FALCON_BIN_DIR`、`IBME_SAGELOLI_RING_NATIVE`。在Windows侧读取实际Git SHA并填入下列`SOURCE_SHA`，WSL必须使用约定Sage环境；预检文件和私有目录都须是新路径：

```sh
export PYTHONPATH=src:. PYTHONDONTWRITEBYTECODE=1
export OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1
SOURCE_SHA=替换为实际40位源码SHA
~/miniconda3/envs/sage/bin/python -m experiments.research.lai_c2_combinations plan \
  --directory /新的预检输出.json
~/miniconda3/envs/sage/bin/python -m experiments.research.lai_c2_combinations run \
  --source-commit "$SOURCE_SHA" --workers 6 \
  --directory "$HOME/.cache/ibme/lai-c2-new-run-01"
```

生成阶段和每个解密进程均有1800秒上限，失败保留现场，无自动换根重试。预检仍是`not_executed`；实际执行以`identity_cases`及进程返回码为准。

## 声明与尚未覆盖

工程沿用既有SHAKE哈希／随机预言机接口；SRGG的原文QROM结论继续按其交付引用，本批不新增ROM、QROM或标准模型安全声明。Lai及各IBS的论文引用和用户确认的安全／匿名性工作前提、无perturbation的Lai采样差异和有限数值误差均沿用既有契约。这批功能运行不构成安全证明，`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`保持原值；C2和不同IBS候选不自动获得等价安全目标。

本批各组仅一次加密，无多根重复、消息长度扫描或统计失败概率；没有新增C2空消息、有效外层认证下的伪造内层拒绝、仓库外wheel／CLI四组合验收。恢复会重新取熵做Lai委派，不计零熵叶密钥恢复。旧Luo收据不重算为本批观察数。其余尚未接入或仍由队友测试目标参数的IBS不由本批补跑；三条暂缓路线保持暂缓。
