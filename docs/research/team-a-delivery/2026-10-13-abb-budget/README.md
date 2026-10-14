# A0：q104完整同组配置的公开误差与资源账本

本批补[同组账本](ledger.json)，输入是当前实跑的完整q104/m832单父/单子配置，数学源码基点d5a2a77。脚本 `experiments/research/abb_rom/public_budget_ledger.py`仅重算公开条件和reference-model公式，不生成密钥、私有几何或H oracle值，不消耗随机数。当前父程序仍运行，算法源码保持冻结。

## 同一输入下分别记账

| 部分 | 指定模型内的公开上界 | 适用范围 |
|---|---:|---|
| AP09根矩阵vs均匀，含原算法rank/有限uniform中止 | 约2^-43.215 | 独立均匀system bytes的实际有限AP09根；**不是2^-128统计距离** |
| 独立u0的有界uniform中止 | n/2^192 | 与上述根单列；整个Setup的该TV贡献是两项并集 |
| 单个不同prefix的SampleR理想rank中止 | 约2^-70.122 | 整矩阵IID Gaussian、最多5次；不是SHAKE实例的安全损失 |
| 单个RandBasis理想rank中止 | 2^-64+1792·2^-128 | m832、K896；不能把epsilon128读作整体rank中止128位 |
| 单次已准入GPV的geometry TV | 832/(2^128-1665)，约2^-118.3 | 仅geometry项，实际basis需通过C1/全部路径/标量域 |
| 2^20次32 B解密的geometry并集 | 约2^-90.3 | 每bit新SamplePre，共2^28次；缺private scalar TV，不能当完整采样误差 |
| 理想噪声的条件寿命界 | 2^-100 | 256bit/2^20封装/error128及范数前提；不覆盖以上其它项 |

表中的“-43/64/90/100”等数字仅是上界的二进制数量级，**不是安全位数**。exact fractions、全配置、模型与调用计数在JSON中。根统计距离来自该具体AP09 d/m2，而不是private basis实测；原rank的小项使精确分数很长，不能裁成0或随意继承一个128位budget。

当前配置最多2个不同prefix、2次私有RandBasis。理想RandBasis每候选零陪集norm尾界 `(1+eps)/(1-eps)·2^-832`、候选最大896次及其并集在账本单列。这不能替代非零解密陪集的坏范数映射；后者仍null。SampleR的scalar耦合、rank上界与native allocation也分别列出，不把某个总失败字段用已知项填满。

数学参考的matrix RO/独立均匀tape和实际SHAKE工程实现分开；目前没有相应indifferentiability或安全归约损失的具体证明，故该项null。private GPV全部标量TV、ToBasis/LLL/GSO工作空间、总体HIBE/IBME可用性和安全参数均未闭合；这些unknown不是0。因此账本**没有给整个系统总失败率或整体TV**，仅使缺口可审查。

## 同组资源，不混成实际耗用

- TrapGen最坏private tape648960 B，u0最坏2496 B，完整Setup最坏651456 B；这些是有界拒绝的公开预算，不是新一次Setup实测字节。
- 每个公开H的SampleR最坏tape2062273740800 B，whole cap16TiB；它是累计可请求字节上界，实际按需读取，不分配约2TB内存。H使用公开tape，private entropy账本不能代它计数。
- 每个完整整数基692224个entry。按当前逐entry最少6 B格式，单基4153344 B，root/parent/leaf三基合计至少12460032 B（不含对象头/嵌套PK等）。这只是该格式下的下界，**不能证明整个MSK/parent必定适合Hybrid16MiB component**。
- 32 B raw CT实际布局2773348 B，低于4MiB capsule；这是公开布局精确计算，未据此称实际加解密通过。进程RSS与所有workspace上界仍null，外部探针使用预先声明的8GiB观察预算。

这些预算与正条件阶段、Sage1536维工具域、formal高n尺寸/难度分开核验；n1仍是困难性负控。formal目标必须重新选完整profile、估计根/密文两角色并解决可执行工具/模型问题，不能通过把这些不同上界都称“128位”放行。

## 提升n时必须重新核验的条件

已逐页核[ABB CRYPTO原稿](../../../../papers/2010_lattice_basis_delegation_agrawal.pdf)PDF8 §2.6/Theorem2：引用的Regev quantum reduction前提是 `q*alpha > 2*sqrt(n)`。当前研究recipe固定qalpha4，对n1/2/3满足这一数值前提；n4为相等，**不满足严格不等式**，更高n也不能直接沿用该noise。满足前提本身仍不证明LWE成本或安全等级；不满足只能说这一引用不适用，不能仅据此声称攻击已成功。

账本加入同q的n1/2/3/4/16/128/256尺寸试算。n128的这条noise前提需要整数scaled width至少23；源中现recipe只接受4，研究代码未在运行中改参数。即使只采用保守Setup维度条件，n128/qbits104至少m79873，已超过当前n64/维度1536输入域；按现格式root basis仅entry至少38278176774 B，raw32 B系数在不计头时265820672 B。AP09全部块/统计距离/有限宽度等还可能使对象更大，这不是完整或安全preset。提升noise后的条件正确性未评估，保持null，不拼接当前n1噪声通过项。

正式候选的第一阻塞因此同时包含：独立参数域/可执行完整基工具、正确noise及有限同组条件、真正的根/密文困难性估计。新试算没有创建高n矩阵或密钥；不能把降低n或只改参数记成另一密码算法。

## 复算与验证

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.abb_rom.public_budget_ledger \
  --output test-results/abb-public-ledger.json

PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -p no:cacheprovider -q \
  tests/test_abb_public_budget_ledger.py
```

Sage **4 passed**：[JUnit](tests.junit.xml)。检查不读熵、当前896/2^28调用范围、完整Setup包含u0、独立rank/geometry/噪声项及缺失项保持null；另检查严格Regev边界与高n输入域。不是原语安全证明或新真实采样。

`security_claim=none / backend_admitted=false / parameters_are_formal=false`。本批只改A专属账本/测试/说明，不修改运行中的primitive、共享protocol/registry/CLI或其它队员文件。
