# 完整 SRGG 研究 IBS 实现计划

**Goal:** 从 `3b50a40` 的真实SRGG组件继续，完成原文Setup/Extract/Sign/Vrfy、冻结五方法、规范对象、固定身份缓存/恢复和实际生命周期。

**Architecture:** 新模块仍在 `experiments/research/candidates/srgg/`。参数/哈希/对象/后端由主代理负责；独立 `full_sampling.py` 实施原文连续Gaussian+固定r随机舍入和block Schur条件采样。公共协议/现有HIBE不修改，后端通过冻结IBS五方法接线，交独立登记提案。

**Tech Stack:** Python标准库、既有SRGG环/几何/gadget、指定WSL Sage、现有 OnlineScalarGaussian；不改变已安装环境。

## 明确的原文解释

以缓存PDF SHA256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152` Algorithms1–8为锚。SampleP下块按固定宽度离散Gaussian，上块逐多项式SampleF；SampleF连续物理协方差为 `(shape-r²I)/(2π)`。图中输入f而根号写d，按f解释并记录。主噪声sigma²=b²r²遵循Table3/Algorithm3/SampleZ配方。

ζζ*=2，Sign中u宽度平方r²后乘ζ，故本研究分支明确选签名扰动减去 `2r²*[y;1][y;1]^T`，命名为“ζ一致解释”；Table3字面r²差异不宣称已获作者勘误。Norm超界按Algorithm7重新执行整个签名尝试，有公开重试帽；内部熵错误/采样中止不偷偷补抽。

完整函数与真实执行不是正式安全准入。连续浮点/有限票据stage没有整个TV证书，HNF后key分布/底层强结论仍未闭合；始终none/false。

## 参数与判据

研究档n8/d1/p257/b31/w3、Q7656287；master两宽度平方均2^23、r²4、用户全向量norm²门2^29；signature两宽度平方均2^37，gamma²=48*2^37。精确检查Q²>4gamma²。该档避免B≫Q的平凡范数区间，但n8挑战仅8bit，保留公开固定点伪造负控，不授予安全等级。

- [x] 先新增完整后端测试并观察缺失功能导致失败。
- [x] `full_sampling.py`：真实normal+随机舍入、block Schur、资源/正定/短读与no-fallback；独立测试。
- [x] `config.py`、`hashing.py`：全参数、四个域/XOF、H(ID)、Hbar(w,M)、完整公钥绑定。
- [x] `objects.py`：public seed/B、秘密CBD1 R、tail key、(z,c)，规范解析与norm/参数/身份绑定；master缓存issued/pending/failed状态恢复。
- [x] `backend.py`与私有运行模块：真实Setup/Extract/Sign/Verify/load_signature；原文norm重试和中止分开。
- [x] 诚实多身份多消息、恢复/新进程、独立商环承诺与范数、规范wire/错误上下文/改签名、冻结协议接线、公开小挑战负控。
- [x] 实际audit/参数-原文-代码映射/登记提案/独立复核，修实质问题，更新当前目录与B任务。
- [x] 提交认领文件，保存精确测试和限制，工作树干净后交付。

完成收据：32次真实签验/缓存与恢复；相关Sage167 passed，无skip；Windows53 passed/11明确Sage skip；独立复核并修precision组合与norm-only retry，TDD修复均有失败与通过记录。

源代码提交 `fc66882`；登记/数值误差与正式安全限制见独立交付。
