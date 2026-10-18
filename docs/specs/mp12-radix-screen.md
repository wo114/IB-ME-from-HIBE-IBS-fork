# CHKP 3m / MP12 高基数联合筛选

`experiments.research.structured_radix_screen` 只做公开参数、有限概率和比较模型筛选。原默认二进制实现、对象/wire、registry、协议均不变；没有生成高维根/父/叶、实现新基数后端或新增论文方案。三条暂缓路线不启动。

## 原文与完整宽度链

固定 `papers/2011_lattice_trapdoors_micciancio.pdf`（2011-09-14作者版，SHA256 `bf1160f088825ed28c343b299f5bc2acdca41cc50293310a03a4506d2fdbdb84`）：Theorem4.1（PDF16–17）明确允许整数基数b≥2，k=ceil(log_b q)，primitive kernel的GS²≤b²+1。§5.2计算型根仍为前导 `[I|Ahat]`；Algorithm3（PDF28）要求Sigma≥(s1(R)²+1)(Sigma_G+2)；Algorithm4（PDF29）逐列完整Gaussian委派。继续使用项目既定作者稿CHKP全3m消费者，未切换出版版2m。

本轮保留原公开Frobenius充分配方，**不引入更紧谱界或新证明任务**。令b=2^a、t=b²+1：

```text
k=ceil(q_bits/a), w=nk, m=2n+w
root_s²=4n+1, B0=2nw·root_s², r²=4K(w,192)
S(B)=max((t+2)r²(1+B), 2tr²(w+B))
parent_s²=S(B0), Dparent=2m-w, B1=Dparent·w·parent_s²
leaf_s²=S(B1), Dleaf=3m, chi=floor(2sqrt(n))+1
```

第一项来自Algorithm3，第二项保留现有扰动拒绝器的trace≤1/2充分条件。a=1恰好返回原7/10系数。每组按其全部宽度重新求通过现有精确整数decoder不等式的最小已证明素数q，不固定旧q缩列。公开k方阶kernel验证完整行列式q与GS界，复用原有限GPV/标量/CDF工具构造证书，**不调用采样方法**。

有限账本保留epsilon/tail/abort192、mass320、precision384、拒绝帽256/192、扰动512、256目标、32 B seed、身份每层86 B、2接收者×2发送者与2^20次封装/H/G预算。结果仍是精确算术/资源获准条件下的统计项，排除整操作熵帽、求解/机器资源中止；不冒充总失败概率或安全位数。宽度超过原标量2^192上限时记为待扩展算术profile，保留比较模型结果，不强行扩cap或补造证书，也不据此否定算法。

## 有限搜索与接受条件

预先固定n={512,1024,2048,3072,4096,6144,8192,12288,16384}，a=1..32，共288组。显式传入其它有限网格时记录完整输入；每轮至多512组。默认进程研究预算8 GiB，沿用A资源实验的预算；同时须在交付中列本机WSL/物理内存，不能把预算当作普适不可能性界。

每组根和密文分开估算：根为一列n维Gaussian secret/error、n个样本；密文为前导误差normal form、完整两块H的2m个样本、rounded-noise的DiscreteGaussian**比较模型**。固定Estimator `53da5982597709ba0fdf94ea37a84d822310fd84`，primal-uSVP LGSA / plain dual，ADPS16经典/量子，共8次/组。维持此前角色定义，不执行公开密钥恢复、伪造或其它实际攻击。

参数研究候选需同时满足：8次均返回有限值且最小log2(rop)≥128，资源条件下累计统计项≤2^-128，原标量域通过。**硬件预算是部署分档，不是参数候选的淘汰条件。** 超过8 GiB或本机WSL/整机内存仍保留候选，单独记录所需硬件与实现改造；缺算术profile记待研究。模型错误/缺测不能算高成本；未知状态单列。128为工程筛选阈值，不是实际HIBE/IBME安全位数或NIST声明。

资源计数应用已交固定公共坐标界的逐项编码规则，含根R/公开根、父R/公开父、256叶，以及原探针存活的H1/H2；不分配这些矩阵。新基数outer codec未实现。计数仍未含Python上下文拷贝、metadata、cache及工作区，所以低于预算仅通过必要条件，不能称为已适配内存。逐项列父/叶proposal标量数和一次父R乘法的逻辑乘积数；不据小n外推时间。时间/RSS保持null。

当前探针的resident计数是**特定对象存活方式的payload估算**，不是算法所需内存的普适下界。释放不再需要的状态、复用公共块、分块/外存计算及更大内存机器可另行实测；不得仅因本机跑不了而否定算法，也不能把payload低于硬件总量当作已能运行。保留全部候选、模型未知和待扩展profile；选定候选后逐级实测与接口验收，不直接改默认配置。

原始筛选收据必须保留原源码版本。`--reclassify-from`只复用完成收据的精确q、证书和估计值，按新策略重算决策，不重跑比较模型；原数学/模型commit不改，新策略commit、模块SHA与输入文件SHA单独记录。初版8 GiB硬门槛的历史决策不再代表当前结论。

## 复跑

在仓库根和指定WSL conda环境运行，输出必须为新路径；估计器目录只读核对固定commit与干净工作树：

```sh
PYTHONPATH=src:. OMP_NUM_THREADS=4 OPENBLAS_NUM_THREADS=1 \
~/miniconda3/envs/sage/bin/python -m experiments.research.structured_radix_screen \
  --estimator-path <固定Estimator目录> --source-commit <固定源码提交> \
  --output test-results/a-radix/new-screen.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.structured_radix_screen \
  --reclassify-from test-results/a-radix/new-screen.json \
  --source-commit <新策略源码提交> --output test-results/a-radix/new-decisions.json
PYTHONPATH=src:. PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_mp12_radix_screen.py
```

公共核算在熵/采样方法被禁止的上下文运行；原私有状态不打开。ROM、论文安全/匿名工作前提及none/false/false沿用，功能测试和模型估算不产生安全证明。
