# C64B 参数旁路补充（非正式准入）

本补充只针对 C64B；原 REPORT.md 及此前9份文件保持历史原样，已核对SHA256未变。仓库只读，HEAD=f079ce10fb6b3d2877465b308caaa30276d9e6f9；本旁路仓库修改为零，不提交，交主AI最终入库。

## 精确候选与约束

κ=64，γ₁=190000，γ₂=60000000000，γ₃=27487784448=(q−1)/10，Extract/Sign帽均4096；其余默认：N=256、k=11、l=10、q=274877844481、root=153250464611、η=1、d=28。候选未写回默认参数。
构造器通过：β₁=64，β₂=12160000；γ₁>β₁、γ₂>β₂、2γ₂=120000000000<q、β₂<γ₃、κ2^(d−1)=8589934592<γ₃。
α=2γ₃=54975568896，q−1=5α，q>2α；固定root的N次/2N次幂分别为−1/1 mod q，帽不超4096。
来源：[参数及构造器73–103行](C:/Users/A/.codex/worktrees/luo-acceptance-evidence/IB-ME-from-HIBE-IBS/src/ibme/ibs/luo_module.py:73)、[舍入条件137–142行](C:/Users/A/.codex/worktrees/luo-acceptance-evidence/IB-ME-from-HIBE-IBS/src/ibme/ibs/luo_module_math.py:137)。

## 两分支见证与实际SIS屏幕

令X=γ₁−β₁=189936，Z=γ₂−β₂−1=59987839999，U=κ2^(d−1)+2γ₃+1=63565503489；保留压缩误差的+1。
已见标签分支：[A|Iₖ]，2816×5376；两块界(2Z+2κX,2U+2κX)=(119999991806,127155318786)，q−1−2B=20567206908>0。
未见标签分支：[A|Iₖ|t]，2816×5632；三块界(2Z,2U,2κ)=(119975679998,127131006978,128)，q−1−2B=20615830524>0。
共同放松框：(2γ₂+2β₂,2U+2β₂,2κ)=(120024320000,127155326978,128)，B=127155326978；2B=254310653956<q−1=274877844480，余量20567190524。
代数来源：[见证/压缩78–109行](C:/Users/A/.codex/worktrees/luo-acceptance-evidence/IB-ME-from-HIBE-IBS/experiments/research/luo_module_security_screen.py:78)。已见标签非零仍依赖缓存标签/均匀密钥立方体及完整视图模拟；未见标签需MLWE均匀t混合、c≠0及CID≠CID′，末块c(CID−CID′)的128<q保证不模消失，不要求挑战模q可逆；“未见”包含已签身份的新标签。[条件113–147行](C:/Users/A/.codex/worktrees/luo-acceptance-evidence/IB-ME-from-HIBE-IBS/experiments/research/luo_module_security_screen.py:113)
只实际估计上述共同框的经典/量子两项；各分支较紧输入仅核验代数，未另跑估计。

| 项 | 先前默认（复用旧结果） | C64B本次 | 差值 |
|---|---:|---:|---:|
| 经典log₂(rop) | 196.808 | 188.340 | −8.468 |
| 量子log₂(rop) | 178.610 | 170.925 | −7.685 |
| BKZ β | 674 | 645 | −29 |

κ不变不代表MSIS成本不变：γ₂增大放宽响应块；γ₃增大使U及误差块明显增大，本例后者主导B，故屏幕成本下降。两项仍高于既有128启发式筛查线，但不能承接论文200位标签，也不是128位安全保证。
固定估计器53da5982597709ba0fdf94ea37a84d822310fd84，干净检出及导入路径通过；ADPS16经典/量子、LGSA、系数无穷范数SIS（n=2816,m=5632）。它放松模块结构/分块界，不覆盖全部代数攻击或完整IBS归约。
两项均exit0；经典墙钟16.007秒、量子9.613秒；总26.869秒，外层180秒上限、每项85秒帽。Sage10.9/Python3.13.15/WSL2/Core Ultra7 255HX。rop不是运行秒数。保留内部Euclidean对照忽略形状模型的警告；返回结果tag为infinity。
MLWE未重跑：N,l,k,q,η完全不变，沿用旧输入n=2560,m=2816,Xs=Xe=Uniform(−1,1)的既有证据；没有网格、安装、签名probe或私钥生成。

## 熵、可用性与准入边界

log₂[binom(256,64)2^64]=267.566935510；泛型量子挑战搜索尺度133.783467755保留，较128仅有5.783的模型余量。它不是QROM归约、具体伪造攻击验证或安全保证；不能把ADPS16量子成本直接称为后量子安全位数。C49旧限制仍保留：挑战熵225.345006274、量子尺度112.672503137。
只执行主AI现有定向dyadic证书作数值复现：ε=1/100、QE=64、QS=65536、QH=2^64，合计log₂中止上界−153.856922986；Sign帽−173.897363077、Extract帽−159.947376266、坏A−302.753155951。QH解码项为−194.709960364。
证书源SHA256=28c0bdaae844ab802c178e6ea820002812e8a6306accb606d14b7692a32eb1b8，运行前后一致；[计算95–167行](C:/Users/A/.codex/worktrees/luo-acceptance-evidence/IB-ME-from-HIBE-IBS/experiments/research/luo_robust_abort_certificate.py:95)。完整1024位整数界保存在JSON，小数只是显示。理想独立源/XOF、随机Setup好A例外集合及有限调用预算是条件；不覆盖OS熵/存储/缓存超额。
主AI称DeepSeek可用性证明1–7/9通过；本旁路未复证或重跑其测试。可用性证书不补齐模拟器/分叉概率与时间损失、ROM到QROM、归一化、SHAKE替换及CHKP组合条件。QH在此仅作解码失败预算，不能直接转成量子安全损失公式。
用户新增实测信息另列为主AI提供、非旁路复跑：C64B为54次Sign/315尝试、compact16383 B/reference29455 B；C49为54/293、compact16062 B，不继承默认16063 B。候选probe总计不是比较性能基准。
结论：数学候选/构造器检查通过，条件可用性数值复现、启发式攻击屏幕完成；security_claim=none，backend_admitted=false，parameters_are_formal=false，approved_security_bits=null。未正式准入、未改默认。

## 交付与复现

新增仅3份：[本补充](C:/Users/A/.dsh/deliverables/CODEX-step22-luo-parameters/C64B-ADDENDUM.md)、[完整JSON](C:/Users/A/.dsh/deliverables/CODEX-step22-luo-parameters/C64B-screen.json)、[只读入口](C:/Users/A/.dsh/deliverables/CODEX-step22-luo-parameters/run_c64b_screen.py)。JSON含来源锚点、精确见证、模型警告、运行记录及旧文件哈希。git diff --check通过，主AI未跟踪文件原样保留。
复现命令（本次已运行，无需再次执行）：
```powershell
wsl -- bash -lc 'PYTHONDONTWRITEBYTECODE=1 GIT_OPTIONAL_LOCKS=0 timeout 180s ~/miniconda3/envs/sage/bin/python -B /mnt/c/Users/A/.dsh/deliverables/CODEX-step22-luo-parameters/run_c64b_screen.py --repo /mnt/c/Users/A/.codex/worktrees/luo-acceptance-evidence/IB-ME-from-HIBE-IBS --estimator-path ~/lattice-estimator'
```
方法沿用scientific-critical-thinking的证据分层；技能不是密码学证据。本补充不扩展先前任务、不覆盖历史结果。

