# PR67 数值研究范围复核

本记录接续[固定旧头的初审](../README.md)。初审的PR66问题继续保留；PR67以`1e735e8d13cfce43a04adc3f9d0430ad47b7e6db`完成原生入口修复与范围修订，满足**隔离数值研究原型**的接收范围。实际合并还须以PR67最终提交的新远端CI为准，不沿用旧头全绿。

## 已修复

- 进入C前验证B/P的int64、star/norms的float64、矩阵维度、norms的长度和连续布局、有限正范数、有限正sigma、1至256的整数线程数；不再依赖可被`-O`删除的形状assert。
- 原生缓存文件名绑定C源码SHA，避免C源码更新后误用旧同名库；C源码和采样递推没有改动。
- 修正root_basis_numpy的入口引用，不再依赖未提交的tmp包。
- 文档及n512脚本说明统一为随机H1/H2目标的数值采样／方程探针，列明固定非密码学随机流、缺少身份消息/PW与公开范数验签、估计器复放欠项。修正576.364×sqrt(49152)约127781.34、log2约16.963的算术；没有将单个实测范数变成公开验签上界。

## 实际验证

在项目规定的WSL `~/miniconda3/envs/sage`、`PYTHONPATH=src:.`、插件自动加载关闭、OpenBLAS/OMP各2线程执行：

```text
~/miniconda3/envs/sage/bin/python -m pytest -q \
  tests/test_wang_pw_numeric_full.py tests/test_wang_pw_numeric_sampler.py \
  tests/test_wang_pw_root_basis_numpy.py tests/test_wang_pw_numeric_native.py \
  --junitxml=test-results/pr66-67-review/pr67-fixed.xml
```

**23 passed，0 skipped，7.68秒**：原4项小规模数值测试，加18项非法ABI输入拒绝和1项独立优化模式进程检查。原4项包含在23中，不能相加为27个不同测试。非法输入测试以空桩观察原生调用，全部在入口前拒绝；合法数值路径仍真实调用C内核。该测试文件由现有`tests/test_wang_pw_*.py` CI通配符收集。

```text
python -O docs/deliveries/2026-10-19-pr66-67-review/followup/verify.py
```

上述只读校验还检查初审记录、源版本、23项JUnit、未改的C源码和两份n512 JSON。完整文件、测试及来源指纹见[record.json](record.json)。没有重新进行n512云端实验或独立重算SIS估计，没有改写作者原始收据。

## 接收后仍未完成

本PR接收的是Wang相关数值工程研究，**不是Wang IBS正式参数完成**。公开身份/消息哈希与PW路径、共同五方法、固定公开验签范数及对应估计、适用的Gaussian与随机条件、持久状态恢复和完整IB-ME仍需各自实际验收。任意整数输入的浮点精度、原生分配和溢出界也未由ABI检查证明。

现有公共Wang后端、算法数量和安全字段不变；研究标记保持none/false/false。没有因接收数值原型而增加任何安全证明任务或启动三条暂缓路线。PR66的数字、网格和跨口径比较问题以及Word修订/页面核验仍待，不能随PR67一并记为已解决。
