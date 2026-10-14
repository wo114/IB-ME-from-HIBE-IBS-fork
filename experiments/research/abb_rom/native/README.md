# 精确 Gram 工具

在 WSL 的 `~/miniconda3/envs/sage` 使用已有 FLINT 3.3.1/GMP 和本机 g++，运行：

```sh
sh experiments/research/abb_rom/native/build_exact_gram.sh
export IBME_EXACT_GRAM_EXECUTABLE="$HOME/.cache/ibme-native-tools/exact-gram-v1/bin/ibme-exact-gram"
```

这是本仓库的小型算术程序，通过 FLINT 的 `fmpz_mat_fflu` 对整数矩阵作精确无分母消元，没有浮点运算、随机数或高斯替代。链接的 FLINT/GMP 为外部依赖，遵守其 LGPL 许可证；本程序源代码随仓库交付，二进制不进入 Git。套件 JSON 不得指定可执行路径。应用把它作为显式安装、可审查的本地依赖；版本、源文件和二进制哈希进入运行收据。

列基 B 的 Gram 矩阵 G=BᵀB 为正定。令 D₀=1，Dᵢ 为前 i 阶主子式。Bareiss 的第 i 个对角元素为 Dᵢ₊₁，故 GS 长度平方为 Dᵢ₊₁/Dᵢ。消元上三角 F 给出 μᵢⱼ=Fᵢⱼ/Fᵢᵢ；以 Bᵀ 扩展 G，右侧相同消元给出 GPV 权重 wᵢⱼ=Fᵢ,ₙ₊ⱼ/Fᵢᵢ。正定输入无需交换行，任何实际交换或奇异输入均拒绝。该式与原有精确 GSO 在 1/2/4/8/16/32 维逐项对照，并对非零 syndrome 的固定随机 GPV 样本做完全相等检查。

Python 仍核对完整核格、公开 GS 上界、精确 size reduction/Lovasz、GPV 平滑条件、每坐标宽度、所有有限中心与随机预算。输入维度≤1536，整数/有理数≤65536 bit，输出≤1 GiB；原生输出放私有临时文件，stderr 不公开。这些算术预算不等于实际 RSS 保证，运行观察器同时统计主进程和所有原生子孙进程。

旧消费者默认保留 Python 精确引擎。仅显式 v4 ABB 使用新引擎。未安装或算术失败中止，无自动降级或重抽密钥。工具不补足 ABB 的正式参数、矩阵随机预言机证明或安全准入。
