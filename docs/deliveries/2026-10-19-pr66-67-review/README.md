# PR66 与 PR67 合入前审查

2026-10-19，以已接收的 main `6f04f2b` 为基线。接收状态 **WIP，两个 PR 暂缓合并**；GitHub 显示可合并，暂缓原因是以下内容和实现问题。没有关闭 PR、覆盖作者分支或改写原始实验收据。

固定审查头：PR66 `6c0e2d23bc39cc27378b65fb38b0acd4b93c30eb`，PR67 `cbbfd442cd3992369570f4d32004a9db0bc5cfd7`。各自两套远端事件检查均为46成功、2项预期手动 strict-security 未运行；两套同内容 CI 不算独立密码学实验。

## PR66 报告

1. **新增表3的维度与其公开来源不一致。** Markdown第204行及Word对应单元格写 n=1024、d=390,208。E13的240条记录没有d=390208；其中q=2^127−1、n=1024的记录只有d=390160或390176。按最小候选行m_bar=130064、w=130048，d=m_bar+2w=390160。应明确选择哪一条参数记录并同步修正Word。
2. **有限网格结论被再次扩大。** 第465行E13用途仍写“门内穷举否定”，与正文及已接收PR65的“621个选定网格探针、非严格预筛、0次精确终审”冲突。第204行的15.2/13.8来自模型b=53搜索下限，不能标成已经得到精确攻击成本的“平凡”。
3. **尺寸对照的因果结论超出证据。** 第208行把Foo–Li候选的公钥比特打包估计和Sageloli实跑序列化公钥称为“同等口径”，再归为路线固有代价。E13明确说明安全目标、参数和尺寸口径不同；这两个点可以做资源示例，不能据此认定同安全级优势或整个路线的固有差距。

独立执行原check_report.py：**182项通过**。这证明现有表格的Word／Markdown一致、旧材料指纹和既有统计等检查通过，不验证上述新增Foo–Li表格是否对应E13具体行。第一次直接运行遇到既存comparison.json的CRLF差异；在固定Git源导出中使用规范字节，并补回git archive按export-ignore省略的原PPT后通过。未更改或忽略任何预期摘要。

本轮未修改Word，也未完成其页面渲染验收。选定Windows文档运行时没有捆绑LibreOffice，当前也没有可调用的soffice。所用[文档技能](C:/Users/youzi/.codex/plugins/cache/openai-primary-runtime/documents/26.1015.12040/skills/documents/SKILL.md)（本机工具路径，不随仓库移交）要求“Run `render_docx.py` to produce `page-<N>.png` images”并检查页面；不能把XML一致性检查称为版式通过。上述已复现内容问题已经足以暂缓本PR。

接收条件：修正表格行、限定网格和比较措辞，将E13记录绑定到新增表格检查，重建Word／validation，并完成修订后页面核验。无需新增密码实验或安全证明。

## PR67 Wang数值原型

承认作者收据中的两档云主机n=512/q=4294967291数值实跑；本轮没有重跑约96GB工作集或把这些外部记录计成本机运行。原有4项小规模测试在约定WSL Sage环境独立复跑：**4 passed、0 skipped**，6.73秒。

1. **C边界缺少输入检查。** gpv_kernel.py第24—32行没有检查B／P的int64、star／norms的float64、norms长度和连续布局、正有限sigma、正整数threads。C按固定类型指针读数组；过短或错误布局的norms有越界读取风险。5项受控输入均到达原生入口。本轮将原生函数换为空桩后观测调用，未执行非法原生访存，也不把空桩结果计作密码学功能测试。形状assert在Python -O下也不是有效边界保护。
2. **n=512路径尚非完整Wang IBS生命周期。** numeric_gpv_np_mp.py第49、74行分别随机生成H1矩阵与H2向量，没有接入身份／消息哈希、Pan–Wagner包装、共同五方法和完整verify。最终只打印方程是否成立，没有执行公开范数判定。应按“数值采样／方程与资源探针”接收，不能据此宣称Wang目标参数和完整IBS已完成。
3. **153.70的范围需要准确保留。** 收据把该数写为单个实测范数130978.66下的SIS启发式估计；它不是预先选定验签上界下的IBS安全等级。按收据sigma=576.364、M=49152，脚本beta=sigma*sqrt(M)约127781.34，log2约16.963，实际范数高约2.50%。若把这个beta用作验签上界，该样本会超界。README第128行的2^17.96另有约一位的算术错误。没有公开验签上界就不能用一个成功样本的范数替代参数界。
4. **采样、随机和复现状态尚未闭合。** float QR／连续正态取整不是论文的精确离散Gaussian；NumPy seed=0和C固定种子xorshift是测试流。sis_scan.py依赖未提交的test-results/lattice-estimator，不固定版本，扫描半径也不包含两条实测精确值；本轮没有独立复跑原153.70估计。root_basis_numpy.py的脚本入口还引用未提交的tmp.numeric_gpv_ibs。

接收条件有两种明确范围：若作为隔离研究探针合并，先修复原生边界、清理不可复放入口并统一上述范围声明和复现来源；**不要求为了接收研究代码而补新的安全证明**。若要宣布Wang参数工作完成，还需要真实身份／消息绑定和PW路径、公共验签范数、适用采样与随机条件、按该固定上界绑定的估计及实际生命周期／恢复验收。公共IBS和IB-ME接入另行验收，不继承本数值探针的完成标记。

## 本轮实执行命令与文件

先分别导出上述固定Git源。git archive会按仓库规则排除原PPT，报告只读检查时须从同一固定提交恢复该已跟踪文件；不要改预期指纹。以下`<PR66源>`、`<PR67源>`分别指固定源目录：

```text
# Codex捆绑文档Python，读取公开报告，不生成Word
python <PR66源>/docs/reports/2026-10-19-research-draft/check_report.py
# 在<PR67源>，按项目约定使用WSL环境
PYTHONPATH=src:. PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 OPENBLAS_NUM_THREADS=2 OMP_NUM_THREADS=2 \
  ~/miniconda3/envs/sage/bin/python -m pytest -q \
  tests/test_wang_pw_numeric_full.py tests/test_wang_pw_numeric_sampler.py \
  tests/test_wang_pw_root_basis_numpy.py --junitxml=<新的报告.xml>
# 在<PR67源>，本目录边界控制脚本明确替换native入口
PYTHONPATH=src:. OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 \
  ~/miniconda3/envs/sage/bin/python <本目录>/boundary_controls.py
# 以下检查仅需普通Python与本仓库Git对象
python -O docs/deliveries/2026-10-19-pr66-67-review/verify.py
```

本轮只增加此审查目录和PROJECT_STATUS审查入口。JUnit只删除hostname，完整结果与时间保留；CI、检查JSON、源指纹及判定见review.json和manifest.json。不修改两个PR的实现、报告、参数或原始n512收据。

安全范围：保持none/false/false；外部Wang n512数据仍为数值研究记录，4项复跑为小规模方程测试（数值采样使用固定测试流），5项native控制不是真实采样实验。本轮没有新安全估计、生产随机目标实例、完整Wang IB-ME、Word页面验收或任何暂缓路线工作。
