# C1：LATTE-3 独立 HIBE 研究实现

用户授权先做C中较容易落地的HIBE。本批基于已合入的`9842b30`，选定LATTE-3，完成独立六方法、五类对象、真实两层路径、固定状态与安装验证。算法与测试冻结提交 **`51c40f81d395b6f7a55896f11f7806f63a241c1b`**，完整接口见[LATTE契约](../../../specs/latte-hibe.md)。没有重写公共协议或IBS，也没有把工具探针计作新的HIBE完成项。

## 选择与来源

| C的HIBE路线 | 已有条件 | 本批决定 |
|---|---|---|
| LATTE | 有完整KeyGen/Delegate/Extract/Encrypt/Decrypt代码，当前Sage环境已有GMP/MPFR/MPC等依赖；已定位COSAC缓冲问题 | 先选这一条；完成实际算法与独立后端，匿名与安全条件继续单列 |
| Lai | 原文已有环陷门及IBE，未确认完整作者HIBE代码/有限参数；标签的非零与逆元要求、两层展开还须核准 | 保留候选，不自行补造原文后宣称复现 |
| Zhang | 原文私钥/可委派陷门与参数疑点未关闭 | 保持储备状态 |

来源为[作者代码公开镜像](https://github.com/cqs-technology/latte/tree/18cfbf9a671fca34785583b58ab9f28e3be21a3c)，固定提交作者Raymond K. Zhao，日期2024-09-27。35份原始源/许可证文件、Git blob SHA1和SHA256保存在[native/upstream](../../../../src/ibme/hibe/latte/native/upstream/UPSTREAM.json)，MIT版权声明保留。原版源文件不改写；`randombytes.c`、`test.c`和CPU周期benchmark不编入桥，不采用作者benchmark中的rand()%q作为身份哈希。Git仅对这份逐字vendor放宽行尾空白检查，保留原blob指纹；本项目实现仍检查正常diff。

[本地作者PDF](../../../../papers/2024_quantum_safe_hibe_zhao.pdf)17页，视觉核对PDF7的Algorithms2–4。KeyGen→一次Delegate→终层Extract对应两个身份层，不要求与ABB的两次BasisDel采用相同内部步骤。只是复用和适配已发表算法，不宣称密码学原创。

## 具体实现

- 真正NTRU根及接收者委派格基；精确系数环检查核方程与环行列式±q，排除只生成子格的情况。
- 终层真实ffSampling/COSAC；保留原生确定性Extract，不读取新外部rng，不冒充新独立随机原像。
- 32 B原生加密、中心二项真实噪声（标准差2）、Decode和完整重加密比较。`framed32`另支持0–28 B普通消息。
- 五类规范对象、完整公钥/参数/路径绑定、非法输入拒绝、失败占位、整树可重入锁和零新密钥生成恢复。
- 原生操作每进程隔离静态状态；修复COSAC实际未读取新Box–Muller缓冲的两处指针，限制AES计数器，用OpenSSL SHAKE256兼容接口替代XKCP链接。源码ABI和二进制指纹在调用/收据中核对。
- wheel带原始源码/许可证及构建入口；`backend_spec()`交付显式登记描述。默认registry、CLI、IBS组合仍未接入。

## 固定配置真实结果

固定作者LATTE-3：`N=1024`、`q=68718428161`、深度2；sigma标准差分别为6777.5879662983919609175926、351968.36683734171059914430、22559988.027951553365675150；FFT高精度设置768 bit，源内浮点为binary128。输入身份两层各86 B，消息32 B，重复次数1。ROM用于公开身份哈希；系统源产生根/委派/加密种子，终层按原版公开目标播种。

**[同一实例原始收据](evidence/lifecycle.json)：1个根、2次Delegate、4次Extract；4个匹配、12个身份错配拒绝、16个原生密文修改拒绝、12个截断/追加/重复字段拒绝。** 五类共12个对象往返；新解释器恢复同一私钥树和4份原密文，4次恢复解密通过，外部熵调用0、密钥/密文重新生成0。恢复仍执行确定性二项采样的原生重加密检查，不将其说成解密不做任何采样运算。

总时间 **9.17351841 s**；根API 2.160844 s（含首次Sage导入）、两次接收者0.289985/0.329919 s，四次终层0.129587–0.153732 s；其余时间包含16次交叉解密、16次篡改重加密检查、规范对象、源码核对和新解释器恢复。父进程峰值RSS222,992 KiB，直接子进程观测最大222,832 KiB，二者不能相加当作进程树峰值。硬件Core Ultra9 275HX，WSL/Sage10.9/Python3.13.14，GCC13.3.0，OMP8/OpenBLAS1；环境和构建收据单列。

公开key 12,678 B；带2×2缓存的master快照331,942 B；parent快照147,128/147,159 B；leaf31,782–31,825 B；4份cipher37,087–37,106 B。它们是本项目完整参数/状态JSON编码，不是论文的压缩尺寸。没有同安全目标基线，不宣称端到端提速或尺寸优胜。

外部种子输入共224 B（根32、两次委派64、四次加密128），内部AES展开字节数未测，不能将224 B当所有Gaussian随机带。两档各4096个固定TEST流的[标量诊断](evidence/gaussian-diagnostics.json)通过均值/二阶矩排错；不把这8192次诊断计入真实系统批次或分布证明。

## 验证、安装和复跑

- 新增单体/公开元数据：**64 passed / 0 skip**。[JUnit](evidence/owned-sage.xml)。
- 加既有复用/装配/绑定回归：**116 passed / 0 skip**，包含上述64，计数不相加。[JUnit](evidence/related-sage.xml)。
- Windows公开检查：**12 passed / 1 Sage模块skip**；跳过不算原生HIBE通过。[JUnit](evidence/windows.xml)。
- [隔离安装](evidence/installed.json)：wheel SHA256 `96541b974c46c1f660588eec5ac49346b62f344f4c6adc3909929113d9e89bd0`；`python -I`下13个provider仅来自目标安装包；原实例密钥零熵复用并解密，另建一套独立安装实例完成六方法链。后者不混入前述2×2统计。
- [源码核对](evidence/source-check.json)：53份运行来源/归档文件与固定提交blob逐字相同，执行前后SHA相同；原生source-id与binary SHA起止相同。开发期Hybrid容量字段缺失导致1 failed/50 passed，已补字段而未放宽原包装条件，原报告保留为[开发失败](evidence/development-hybrid-capacity.xml)。

在仓库根、指定WSL环境执行，私有目录使用新名称；已存在/失败目录只观察或恢复，不覆盖后重跑：

```sh
export PYTHONPATH="$PWD/src:$PWD"
export OMP_NUM_THREADS=8 OPENBLAS_NUM_THREADS=1
~/miniconda3/envs/sage/bin/python -m ibme.hibe.latte.native.build
~/miniconda3/envs/sage/bin/python -m pytest -p no:cacheprovider -q \
  tests/test_latte_hibe.py tests/test_latte_metadata.py tests/test_latte_reuse_probe.py \
  tests/test_assembly.py tests/test_hybrid_key_binding.py
~/miniconda3/envs/sage/bin/python -u -m experiments.research.latte_hibe_probe \
  --private-directory test-results/latte3-new/private --source-commit <固定提交>
~/miniconda3/envs/sage/bin/python -m experiments.research.latte_hibe_probe \
  --private-directory <原实物目录> --restore-only
```

API示例：

```python
from ibme.hibe.latte import LATTEHIBE, LATTEParams
b = LATTEHIBE()
pk, master = b.setup(LATTEParams())
receiver = b.extract(master, b"Receiver")
sender = b.derive(receiver, b"Sender")
ct = b.encrypt(pk, b"Receiver", b"Sender", bytes(range(32)))
assert b.decrypt(sender, ct) == bytes(range(32))
```

## 安全边界与未完成项

这是独立HIBE的研究执行交付。作者参数、精确方程、源码复用、诚实解密与有限负例不等于安全准入。原文ID-IND-CCA不自动蕴含接收者匿名性；本批不授予Wang匿名组合前提。新的身份域/公钥绑定、实际Extract种子输入、COSAC修订、FFT/有限精度和有界中止相对原定理的对应仍须核验。整体TV/RD、总体失败及完整攻击成本没有闭合数值，保持null。

固定 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`；不宣称NIST等级、CCA/匿名/QROM正式安全、完整IBME或公平性能优势。状态没有外部认证和防回滚；接口绑定仅核代数和上下文。正式条件、默认登记/CLI和真实IBS配对是后续工作。

本批跨目录修改仅为独立模块打包的`pyproject.toml`，以及统筹维护的公共规格/候选和状态说明；没有改其它owner的算法。完整命令、来源/证据SHA、限制和文件列表见[audit.json](audit.json)及[files-changed.txt](files-changed.txt)。所有私钥、实际原像/随机种子和状态仍在ignored测试目录，不进交付材料。
