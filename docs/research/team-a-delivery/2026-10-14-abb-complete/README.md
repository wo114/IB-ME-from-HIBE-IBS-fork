# A交付：ABB真实完整流程与Luo组合已通过

本页更新A2的当前实测状态；前批WIP/失败收据仍保留为历史，不能覆盖本页当前结论。功能研究路径已经完成，正式安全参数/模型没有准入。

## 本轮已实际执行

| 验收 | 输入与结果 | 证据 |
|---|---|---|
| ABB完整原语 | 同一AP09根、真实父/叶BasisDel+高斯RandBasis、两层身份各86 B、32 B载荷、256 noisy Encrypt、256新SamplePre Decrypt，五角色codec及固定树恢复通过；367.925721 s、61182230私有随机字节 | [原语收据](evidence/hibe-lifecycle.json)，数学/程序冻结提交e712713 |
| 已完成实物契约 | 真实五对象/公钥身份绑定、源未变、固定树恢复私有熵0、wire/context控制、32 B固定测试熵重放；3 passed，56.16 s，无skip | [JUnit](evidence/real-contract-tests.xml) |
| ABB+Luo+C64B/compact+Hybrid+BYTEAUTH | 同一真实ABB密钥，32 B应用消息，Luo独立参数；诚实恢复、三个身份错配、截断/追加/重复/版本/字节/OTS签名修改、新OTS重签、可解析IBS签名修改、随机IBS伪造、组合对象恢复共22检查通过，320.500262 s | [组合收据](evidence/abb-luo-combination.json)，冻结e712713 |
| A登记提案 | 现有BackendSpec的完整参数/四密钥decoder/密文reader/尺寸/绑定/缓存及前置依赖检查；调用者自有registry装配q26+Luo不消耗私有熵，2 passed | [JUnit](evidence/registration-tests.xml)，默认公共registry由统筹接入 |
| 两接收者×两发送者 | 同一完成根的独立状态副本，实际生成额外Carol父和三个新叶；四条完整32 B诚实路径、真正错误接收/发送/双错私钥的数学对照、四叶绑定与完整树恢复私有熵0，共26检查通过，945.580302 s | [两层多地址收据](evidence/two-by-two.json)，冻结e50882e；运行数学/采样源码未变，runner在Git中从该提交至归档也未变 |
| 真实字节API的公开n1攻击 | 只读取public.bin，默认系统随机数新加密32 B，攻击仅用公钥/身份及密文唯一恢复256原始比特；新根/私钥/私钥文件读取均0，10.781997 s | [负控收据](evidence/public-attack.json)，这确认当前研究配置不安全 |

真实系统随机数与固定测试熵分别记录，不能把两者重复测试数相加。原语收据的唯一根、同组配置、完整输入和结束源码/二进制指纹均核对；没有把两个失败实例或不同配置的阶段拼成成功。原始私钥、矩阵、seed、密文和运行状态都留在忽略的本地私有目录。

## 原理及修复

ABB10-ROM固定维度：AP09 Algorithm1/§3.3真实根；SampleR为整矩阵IID离散Gaussian并以整体模q可逆为判据；BasisDel执行R*T、完整ToBasis、实际GPV/RandBasis两层；逐bit加密每次新s和真实舍入噪声；解密逐bit新SamplePre并检查方程及范数。旧教学`abb10`没有改名或作为替代。

修复只涉及实现和研究输入：FLINT Bareiss给出与原有有理GSO完全一致的长度、μ和GPV权重，已逐项/同随机数样本对照；固定Flatter/fpLLL后精确核完整格、size reduction、Lovasz和预声明质量。根实际GS²≤256，父/叶实际GS²≤65536；下一层宽度从实际要求的质量前提计算。未满足便中止并保留FAILED，不重抽同地址、不降低检查。规范化拒绝与条件化分布尚无整体安全论证。

q22/256父门先失败；只读同根、新Carol地址诊断明确在真实RandBasis之后的GS门失败，原Bob/Carol失败都保留。q26为独立新实例、新快照和重新计算的全条件，不改旧实例门。较大q80配置停止后保留FAILED：3231.277521 s，只有Setup通过，私有熵80180、源未变；因优先完成已可运行的基本路线而停止额外配置试验，不能将其写成数学不可能、资源越界或q26阶段结果。见[中止收据](evidence/q80-interrupted.json)。

## 完整参数、字节与口径

q26/v6：n1、素数q33554467；随机块52、m1=52、m2=156，固定维度208，Hadamard23；R²74752，sigma1²7045668434608128，sigma2²1803691119259680768，tau²19136512；epsilon64、error128、qalpha4、最多2²⁰封装，父/子地址容量各2，86/86 B身份及32 Bseed。原语规范wire：PK1806、主状态787743、父状态525219、叶262605、密文215050 B；含Luo/Hybrid/BYTEAUTH组合密文330201 B。父状态包含已经发放的叶，尺寸不是纯父基大小。

软件：WSL Linux6.18.33.2、Sage10.9、Python3.13.14、Core Ultra9 275HX；Flatter固定d2b8026、FLINT3.3.1精确本地工具、OMP8/OpenBLAS1，源码/二进制SHA256在各收据。各完整运行1次；以上时间不是中位数、稳定性估计或公平安全参数排名。

模型仍是SHAKE矩阵RO工程实现与有限Gaussian，`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。n1是明确可公开恢复的教学负控；完整功能成功不能修复参数不安全，不能证明LWE、匿名HIBE或王老师组合前提。正式高n估计、可引用归约前提、矩阵RO映射、各质量拒绝/空间失败概率未闭合。G-run研究交接已可执行，G-formal仍未完成。

正式资源先看[前批参数/任务口径](../2026-10-13-handoff/README.md)及独立公开预算。示例n128、log2q约80若沿当前8nlogq构造会有81920维、每份完整基6710886400个整数，仅现有私有wire的6 B/项下界就超过40 GB；该示例不是安全参数。当前AP09接口n≤64、工具维度≤1536、全整数内容1 GiB，也只前置放行已核研究噪声配置。正式n必须独立选择/估计噪声和宽度；不能把n1的输入、测试或资源假设直接升级。

## 运行与交接

先构建[精确工具](../../../../experiments/research/abb_rom/native/README.md)，在WSL设置：

```sh
export PATH="$HOME/.cache/ibme-native-tools/flatter-d2b8026/bin:$PATH"
export IBME_EXACT_GRAM_EXECUTABLE="$HOME/.cache/ibme-native-tools/exact-gram-v1/bin/ibme-exact-gram"
export OMP_NUM_THREADS=8 OPENBLAS_NUM_THREADS=1
export PYTHONPATH="$PWD/src:$PWD"
```

新一次完整实例：以`q26_level_quality_research_params().to_bytes()`保存完整参数；执行`python -m experiments.research.abb_rom.hibe_probe --private-directory <新目录> --params-file <快照> --baseline-commit <冻结提交> --max-rss-mib 8192`。Windows工作树在WSL不可直接读Windows的Git目录，提交号由Windows Git取得后明确传入，不把含CR文本混入参数。已有FAILED地址禁止重试。

契约命令：`IBME_ABB_REAL_PRIVATE_DIR=test-results/abb-q26-levels/private IBME_ABB_REAL_REPLAY=1 ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_abb_real_lifecycle_contract.py`。组合入口[执行说明](../2026-10-14-exact-gram/COMBINATION.md)，将私有源目录换为q26完成目录；结果与本页归档证据一致。

代码交接分组：`src/ibme/hibe/abb_rom/{backend,params,profiles,primitives,parameter_screen,key_validation,registration}.py`；`src/ibme/lattice/matrix_sampling/{gpv,basis,exact_gram}.py`；`experiments/research/abb_rom/`三个真实probe与本地C++构建；对应六组新tests和研究证据。当前实现提交d6aea49、988bc13、27b7b78、94a3d3d、732b032、e712713、e50882e、b56bd72、986e786；合并f5ca17a保留已独立审核合并的PR14、16—20及其模块边界。

统筹可直接把`abb_rom.registration.backend_spec()`加入调用者自有registry，选择`n1-q26-level-quality-research`、Luo的`c64b_params()`、compact/Hybrid/BYTEAUTH；保留所有none/false。公共默认registry/CLI及正式安全准入由统筹处理；A没有擅自替换其它后端默认或原始状态。

CI旧27b7b78有两项发送者快照发布测试要求失败后自动重试，与已合入的`transport-and-state`§2.3明确保留pending/禁止重发冲突；实现符合现规范。本轮只修旧测试断言，保留主状态先提交、临时文件清理、主缓存是否成功保存的原检查，并增加pending保留、重试在重新加载/采样前拒绝、无密钥发布和主字节不变的检查。Windows相关45 passed/3需要WSL的skip，14.46秒；不修改CLI或放松状态规则，见[JUnit](evidence/state-transaction-tests.xml)。
