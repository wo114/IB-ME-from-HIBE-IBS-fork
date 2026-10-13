# A 第一批：公开 HIBE 研究后端与真实组合交接

基点 `57a02e5`，2026-10-12。A 目标仍进行中；本批完成可调用的 MP12 变体研究后端及一条真实组合，没有完成 A2 ABB-ROM、公共工具部署、正式参数或原 CHKP 安全准入。[执行收据](lifecycle.json)、[九组同输入投影](parameter-plan.json)、[审计与源指纹](audit.json)分别记录实测、估算和未完成项。

## 1. 这次具体实现了什么

`computational_root.py` 实现 MP12 §5.2/PDF25 的计算型 GenTrap：公开前缀 `[I_n | Â_n×n]`，独立有限 Gaussian `R=[R1;R2]`，尾部 `G−R1−ÂR2`。它依赖正常形式 decision-LWE 的伪随机性，**不是**关闭旧统计根的 regularity 检查；原统计根仍拒绝相同薄尺寸。多列归约损失与攻击估计尚未完成。原稿见 [MP12](../../../../papers/2011_lattice_trapdoors_micciancio.pdf)。

生成前声明整矩阵 Frobenius 截断 `Q=s_R²·(2n)·nk`，超限整次中止，不重抽。零中心 Gaussian 的 Markov/Poisson 上界核到逐维因子≤1/2，因此理想坏范数≤2^-d；有限采样和中止另外耦合。由 MP12 Lemma5.3 给公开 GS² 充分界 `10(1+Q)`，不使用实际秘密范数调参。qFALL 只对已生成秘密做确定性完整基转换，Sage 独立验矩阵方程、完整核格和 GS；native 不发熵。

`hibe_reference.py` 提供冻结的六方法 setup/extract/derive/encrypt/decrypt/load_ciphertext，加公开密钥绑定能力。真实 Extract 用 MP12 Algorithm4 与有限 GPV 委派，真实 Derive 采 256 个实际 H/G 目标原像；父/叶地址固定，失败状态保存且不重试。H/G 和共享前导噪声布局沿用 CHKP 研究组件，普通隐私/认证等组合模型仍需引用对应，不能直接借用原 CHKP RandBasis 定理。

新 PK/MSK/一级/二级/密文均有规范版本、完整参数/公钥/身份绑定、长度与整数/资源检查、严格恢复。原始 HIBE 容量 0—32 B，补零和长度字段是显式适配；Hybrid 使用完整 32 B seed。raw CPA 容错与 BYTEAUTH 拒绝责任分开。

`hibe_registry.py` 给真正可执行的自定义 BackendSpec 和 registry，公用 `make_suite → validate_suite → build_runtime` 直接装配到现有 Luo 模格 compact、Hybrid 和 BYTEAUTH。default registry、CLI、队友后端和原参数 guard 都没有改。这是 **source checkout + Sage + 私有转换 engine** 的研究后端，尚未安装到 wheel 或默认入口。

## 2. 同组参数及原文—代码对应

| 项目 | 同一配置 / 对应 |
|---|---|
| n/q/k；根 m_bar/m | `2 / 549755813911 / 40`；`4 / 84` |
| 根 Gaussian s_R² / Q / 公开 GS² | `16 / 5120 / 51210`；MP12 §5.2/Lemma5.3，实际有限 scalar |
| 父采样前缀/列/完整维度 | `88 / 80 / 168`；Algorithm4，额外扩展列进入前缀，最后 nk 列作尾部 |
| s1² / 父公开 GS² | `28063080 / 1975640832010`；有限 GPV C1-exec、整列范数截断与公开 Frobenius 界 |
| 叶维度 / s2² / 固定目标数 | `252 / 1082651175941480 / 256`；真实两层 H/G、有限 GPV、固定状态 |
| 离散 Gaussian | FirstFiniteOptions 默认：tail128/mass256/precision320/abort128；完整 options 在收据，不用均匀数替代 |
| 加密噪声 | 原文取整连续 Gaussian，`α=4/q`；tail128/mass192/precision256，统计方差与宽度分开 |
| 条件正确性 | error_bits128、256 bit、2^20 封装；范数前提下寿命界2^-100，key/采样/中止/实现误差另计，**不是安全位数** |
| 身份 / 应用输入 | Bob/Alice 为 3/5 B；内部各86 B；明文57 B；最多2接收者、每个2发送者 |
| 模型与声明 | 经典 ROM 条件待对应；LWE 根与密文两组参数分列；none/false，非正式教学调试配置，无 QROM/标准模型/等级声明 |

Luo 的完整独立参数快照保存在收据；使用当前分支默认模格版及 compact，不冒称已接收 PR #9 C64B helper。两个参数不用相同模数/维度。

## 3. 本次真实执行与负面对照

一次系统随机批次生成 **1 根、2 父、4 个固定叶（每叶256原像）**。21 项真实检查全部通过：四种身份匹配；wire/context/签名改动、截断/追加/重复；公开换 OTS 重签；公钥/接收者编码往返和畸形拒绝；同址不耗熵复用；新解释器恢复和规范字节一致。恢复配置的 native engine 是不存在的路径，熵提供者调用即失败，因此不是又生成一套 key 后称恢复。

| 实际规范尺寸 | 字节 |
|---|---:|
| 完整 IBME 公钥 / 主状态 | 249836 / 2864602 |
| 发送密钥 | 313695 |
| Bob 接收状态（2个叶） | 1232812 |
| 完整 IBME 密文 / 内层种子密文 | 117520 / 2664 |

总过程218.923 s，含发钥、四叶、组合攻击、恢复和公开攻击，一批/一次；单元检查曾并行，不能把它当公平性能排名或 A+B<C 收益。CPU Intel Core Ultra9 275HX，Windows宿主/WSL Linux，Sage10.9/Python3.13.14；软件细目见审计。明文和密钥/种子/基/原像留在被忽略私有目录，Git 只归档公共收据、测试与源指纹。

**n=2 的公开攻击也实际成功。** 利用公开 I 列的 `s_i+e_i`，枚举有限噪声[-46,46]^2，8649 次，用全前导筛选后唯一恢复 DEM 并读出测试明文；函数只收公钥和密文，没有私钥/原像/RNG。这是安全负控通过，不是隐私安全通过。该 profile 不进入正式推荐或三个代表。

## 4. 正式尺寸尚缺什么

九组投影全使用同一链的根宽度、父/叶公开界、实际格式下界、根/密文 LWE 角色和原执行 cap；不生成高维 key、不调整 guard。n128/q=2^61−1 的父完整基仅编码下界就1,560,674,304 B，既有 root/GPV/宽度域都未就绪。n256 条件噪声检查失败；n512及以上超过65536检查域，噪声是 `null/not-evaluated`，不能称数学失败或通过。

“较小 m_bar”没有自动解决完整基与 GPV 扩展成本。下一步 A0/A3 必须处理实际可部署工具/表示、引用中可用的分布/谱界和两角色攻击估计，再选择真实参数；不把上面范围外数值放行、不再单独增加 n2 样本。MP12 Algorithm3 尚未用于此后端；旧在线实现与目标维度/资源需独立核验后才能接入。

本批同时给 A1 可复用的对象/状态/装配实物。原 CHKP 的 RandBasis 路径、ABB-ROM 忠实实例和储备模型继续按 A 任务书推进，不因某一参数失败全停，也不称 A 已完成。

## 5. 可重放命令与交接

在源码根目录，先按 [qFALL 构建入口](../../../../experiments/research/reuse/qfall_probe/Cargo.toml)构建 `ibme-qfall-private-root` 到被忽略 `test-results/qfall-target/release/`。本机复用了相同冻结源编译的 cache，其 SHA在审计；不是另装未经核验 RNG。

```bash
PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -m experiments.research.first_suite.hibe_probe \
  --private-directory test-results/a-hibe-new/private --output test-results/a-hibe-new/result.json

PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -m experiments.research.first_suite.hibe_probe \
  --restore-only test-results/a-hibe-new/private

PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -m experiments.research.first_suite.computational_parameter_plan \
  --output test-results/a-hibe-new/parameter-plan.json

IBME_A_HIBE_PRIVATE_DIR=test-results/a-hibe-new/private PYTHONPATH=src \
  ~/miniconda3/envs/sage/bin/python -m pytest -p no:cacheprovider -q --tb=short \
  tests/test_first_suite_hibe_reference.py
```

测试 fixture 默认定位 `test-results/a-hibe-contract/private`，上面换目录复跑用环境变量指定刚生成的实物（不拷进 Git）；没有实物或 Sage 时明确 skip，不当通过。可移交参考实现来源：`first_suite/computational_root.py`、`hibe_reference.py`、`hibe_registry.py`、`hibe_probe.py`、`computational_parameter_plan.py`及专属测试。

最后在参数解析资源加固和可指定fixture路径后，新增 Sage 测试 **48 passed**，无 skip；此前40/2/44/1/2为开发范围，不重复累加。框架回归85 passed。实际组合在参数解析加固前执行，数学/参数/wire均未改变；最终源再次新进程无engine/无熵恢复通过。命令、JUnit和最终源指纹见审计，最终指纹不冒称原运行前采集；静态接线不替代组合。

第一次探针因错用 SuiteConfig 字节方法，在 Setup/熵消费前终止，私有目录仅有pending；改用现有 to_json/from_json 后在新目录执行一次真实批次，旧现场保留。注册提案同时按 Hybrid 契约使用合法固定 wire ID，没有改变公共接口来绕过检查。

本批提交只涉及 A 的新参考/测试和当前进度/交付文档。WIP：正式参数/模型、发布包、原CHKP与ABB、全部就绪池比较、独立参数攻击仍缺；目标保持 active。

修改文件清单：

- 新增 `experiments/research/first_suite/computational_root.py`、`hibe_reference.py`、`hibe_registry.py`、`hibe_probe.py`、`computational_parameter_plan.py`。
- 新增 `tests/test_first_suite_hibe_reference.py`。
- 新增本目录 `README.md`、`lifecycle.json`、`parameter-plan.json`、`audit.json`、`sage-final.junit.xml`、`framework.junit.xml`。
- 更新 `docs/PROJECT_STATUS.md`、`docs/ALGORITHM_CATALOG.md`、`docs/workplans/2026-10-12/tasks.json`；公共接口、src/密码代码和队友既有文件不改。进度文档跨文件是为避免旧“无公开接口”与本批实际证据冲突。

提交信息：`feat(hibe): assemble finite MP12 CHKP research backend and real lifecycle`。以交付提交和 PR 的实际哈希定位版本，本文不自引用提交哈希。
