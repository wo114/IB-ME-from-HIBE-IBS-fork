# ABB 卡住的规约步骤：现成引擎接入

本批先合入已审查的 PR14/16，并实际处理 A 公共工具的四处冲突。新工作区与旧工作区分开，原有未提交参数筛查和失败发钥现场保留。

ABB 的 BasisDel 仍执行实际 R*T、完整 ToBasis、真实有限 Gaussian RandBasis；每 bit Decrypt 仍重新 SamplePre。宽度、qalpha4、同组噪声门和失败地址语义不降低。旧 v1 配置继续可解码。

`matrix-flatter-lll-075-0501-exact074-v2` 是预先选择的新规约配置：用公开的 [flatter](https://github.com/keeganryan/flatter) 现成实现预处理，再执行固定 fpLLL .75/.501 和精确 size≤.5/Lovasz≥.74/GS 上界。输入、外部提案、输出分别核完整公开核格；错误外部输出立即拒绝。规约不再维护巨大的变换矩阵，两端同一完整核格的成员关系和指数足以核验相等。不是新的密码方案。

外部源码固定 `d2b8026f29b4a69e987b15d4b240f8a5053275d3`（LGPLv3）；本机链接指定 conda Sage 的 GMP/MPFR/OpenBLAS，Eigen 3.4.0，工具单独安装于本地 cache，源码/二进制不嵌入项目。Sage 原语仍运行在 `~/miniconda3/envs/sage`；启用前要求本机 PATH 能发现 flatter，不由公开 JSON 指定可执行程序，不回退。

测试包括真实外部规约，以及故意返回零基、外国格、真子格的拒绝；相关回归约定及原始 JUnit在本地 test-results。首次测试暴露 Sage feature 名称大小写，已按已安装源码修正。v2 使用独立新实例，不重试旧 FAILED 地址。

输入沿用 q104/n1/m832、86 B 两层身份、32 B seed、epsilon/error128、同组公开宽度；仅规约配置明确版本化。新实例的完整父、叶和256bit加解密结果必须实际产生后才能写通过，当前尚未完成。n1研究输入不安全，所有 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false` 保留。
