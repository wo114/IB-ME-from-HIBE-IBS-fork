# A3/A2：公开规范核格基的精确计算与首次q104中断

基点 `9da3eca2d687352c07b4e3d559f7f1e25515a805`，2026-10-13。原q104纵向程序已退出1，源码指纹前后相同；本批在该进程结束后修改确定性规范基计算，没有在运行中换算法，也没有重发失败地址。

## 实测及固定失败地址

一次真实q104/m832/AP09 Setup通过：6.126741 s、134888私有随机字节。随后父过程仍在通用HNF，显式SIGINT结束；总1371.057 s，峰值RSS5308124 KiB，私有随机字节总数仍134888，故本次父RandBasis尚未消耗私有熵。public SampleR使用SHAKE公开tape，不能把这134888写为整条路径的所有随机字节。

对应[完整收据](first-q104-interrupted.json)记录实际root1、父FAILED、完整HIBE false；[操作中断请求](operator-interruption.json)单列，非数学/Gaussian失败或自动RSS越界。原pending及权威 `master.bin`均保留。新进程 `--restore-only`验证失败父地址禁止发钥，私有熵调用0；后续新实例必须新目录/新公钥，原地址不解除、不回滚。

## 保持唯一column HNF及原始ToBasis

已验证的完整格由公开模q行空间唯一确定；wide `canonical_basis`以右侧主元直接求它的lower column HNF。步骤是反转公开列顺序，求满秩field主元及free变量，将解用[0,q)规范lift写入匹配坐标，反转行/列。输出核查lower triangular、对角1/q、`0<=h[i,j]<h[i,i]`以及完整KernelBasis的包含关系与index q^n。这些条件唯一确定原来的Sage column HNF。

该公开基是长的代数anchor，**不是密码陷门**。后续仍以真实R·T或实际RandBasis向量作S，精确完成T·R=S，并验完整格/GS和真正Gaussian随机化；没有直接将公共基当私钥、跳过SampleR/BasisDel/RandBasis或更换宽度。旧legacy canonical/HNF实现及边界保持。wide Z的row HNF仍固定`padic/proof=True`，没有删除整格补全。

wide的两个已知三角系统也改为精确整数代入：先解lower B·Z=S，再解U·R=Z；每行/列要求整除、验证完整因子方程，不再向通用QQ solver隐藏已知三角结构。结果仍是同一Z/U/T，非整除输入严格拒绝。独立测试以有理solve对照非单位正对角、带符号coeff及非整除反例。

测试包括前导/非前导/最右主元、满秩多行、q2、同一格不同秘密表示：新基与通用column HNF逐项一致。原格补全、旧固定Gaussian随机tape和normalizer输出差分继续通过。最终完整Sage回归 **227 passed / 3 skipped**，缺两个旧native私有witness及一个84维私有witness不当pass；[JUnit](sage.junit.xml)。开发中一处测试错误调用Sage不存在的Matrix.copy（1 fail/226 pass），已改用独立matrix构造并重跑通过，不是矩阵算法失败。

在已生成q104实例的**公开根矩阵**上直接规范化实测1.099014 s，峰值RSS397380 KiB，完整格与规范形验证通过，[公共算术收据](direct-canonical-public.json)。该收据的源指纹在三角solver改动之前采集；其canonical函数和输入/输出未改变，不改写旧SHA冒称最终source。输入是明确公开代数基，私有熵0、TrapGen false；没有再生成根或发钥。此操作与之前1371秒父程序的计时边界不同，不做加速比或完整HIBE性能声明。

所有实验是一次/一输入，身份为现有父内部86 B，尚未生成诚实叶或做32 B闭环。CPU/软件同前批Intel Core Ultra9 275HX/WSL/Sage10.9/Python3.13.14；完整参数及源指纹见收据。Sage按 `~/miniconda3/envs/sage`，私钥/运行状态/native原始栈保持ignored。

最终[审计](audit.json)及[隔离安装验收](installed-api.json)：wheel重新构建并安装到仓库外`/tmp`，Sage `-I`，71个provider全部来自安装包，源码目录provider0；实际宽scalar、宽模数SampleR/左右逆、现有真实失败主状态恢复及禁止重发均通过（私有发钥熵调用0）。安装不等于诚实HIBE闭环；probe仍明确按source checkout运行。wheel SHA在审计，安装目录没有改全局Sage环境。

`security_claim=none / backend_admitted=false / parameters_are_formal=false`。n1困难性负控及矩阵RO工程实例缺口仍在；确定性canonical优化不新增密码算法或安全方案。WIP：新源码完整纵向、正式高n和完整组合尚待实际执行。
