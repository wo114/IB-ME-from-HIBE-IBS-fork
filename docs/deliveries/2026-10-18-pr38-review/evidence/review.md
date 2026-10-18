固定 head `2e1039247c2e28bae70351120575b2c782753e84` 的源码与研究证据复核通过；本评论补齐作者原先声明缺少的规定环境验收。它是公开数值筛查和强制不准入证书，可按该范围接收，仍须等此 head 的远端检查全部结束再合并。

- 对照实际下载并核验SHA256的作者网站稿（`https://people.cs.rutgers.edu/~dc789/bonsai.pdf`，`87b5bff4...a90442f`），完整检查PDF20–21：ROHIBE确为t*m、A0到A_(t-1)，Theorem5.3与模拟器为d*m和d−1个H前缀。仓库后期作者稿PDF22的定义为(t+1)m，而同页Theorem5.2/模拟器仍为d*m；版本不一致确实存在。aid表示adaptive identity，匿名填充是另行对应的论证。未开始标准模型路线。
- 当前后端/wire未被悄悄修改。筛查器单独记录数值门、未实现的出版版布局、RandBasis/等价秘密分布、Lemma2.4(4)、字面噪声、攻击覆盖与资源门；正式准入字段始终none/false/false。高维对象未分配，没有熵/发钥/采样调用。
- 规定WSL conda Sage10.9/Python3.13.14：`PYTHONPATH=src:. PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 OMP_NUM_THREADS=4 OPENBLAS_NUM_THREADS=1 ~/miniconda3/envs/sage/bin/python -m pytest -q -p no:cacheprovider tests/test_chkp_published_formal_screen.py tests/test_mp12_target_screen.py --junitxml=test-results/pr-review-2026-10-18/pr38-target.xml`：16 passed / 0 skipped。
- 同环境运行 `ci/run.py run a-structured-hg --output test-results/pr-review-2026-10-18/pr38-a-structured`：186 passed / 0 skipped，153.12 s；该集合与上述定向有交叠，不相加。
- 独立干净Lattice Estimator固定`53da5982597709ba0fdf94ea37a84d822310fd84`，用新输出路径执行 `-m experiments.research.chkp_published_formal_screen --estimator-path <固定checkout> --output <新收据>`：16个比较模型全部有限返回，整个target对象与作者归档逐字段完全相同，包括q667066744249733736124919、投影指数131、根/密文扣声明损失241.78810871646104/230.10500000000002。环境和实际路径另外记录，未冒充同一次运行。
- 最新分支已基于main的`58a50bd`整理，初版进度文档冲突已消除；新筛查器与测试字节未变化。源文件/公开收据指纹及范围`git diff --check origin/main...HEAD`通过。

数值投影不是完整ROM概率证书，理想离散Gaussian比较不是字面rounded-continuous安全估计，已测子集扣损失也不是具体安全位。单父R现表示约507 GB只是公开编码下界，不是峰值内存实测。正式参数、秘密分布/原文有限常数、出版版可运行后端与Wang组合仍WIP。
