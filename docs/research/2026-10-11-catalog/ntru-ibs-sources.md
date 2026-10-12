# Xie–Hu–Gao–Gao 2016 NTRU IBS：来源与接入状态

核对日期：2026-10-11。用户已要求纳入 IBS 候选。当前状态为**论文已归档、原作者 IBS 代码未在已检索范围内找到、尚无本仓库实现或准入参数**。本记录服务于独立 IBS 模块选型，不预先绑定某个 HIBE。

## 1. 论文身份与归档

- 标题：*Efficient identity-based signature over NTRU lattice*。
- 作者：Jia Xie、Yu-pu Hu、Jun-tao Gao、Wen Gao。
- 出版：Frontiers of Information Technology & Electronic Engineering，2016，17(2)，135–142；DOI `10.1631/FITEE.1500197`。这是身份基签名；同组作者的 certificateless signature 是另一篇论文。身份已与[期刊官方记录](https://journal.hep.com.cn/fitee/EN/1160009795640025580)及 Crossref 对照。
- 本地原始 PDF：[2016_ntru_ibs_xie.pdf](../../../papers/2016_ntru_ibs_xie.pdf)，来自 [Springer 官方 PDF](https://link.springer.com/content/pdf/10.1631/FITEE.1500197.pdf)；8 页、548574 字节，`pdfinfo` 和正文提取可读，首页标题／作者／DOI 一致。
- SHA-256：`0797847601224a3743cdf1597cad74aa31cfa966c5b466e4b945af07762a0559`。
- 完整获取记录：[ntru-ibs-fetch-2026-10-11.json](../../../papers/ntru-ibs-fetch-2026-10-11.json)。本次核对了算法、参数和结论相关章节，并渲染检查印刷页 139、141；没有完成全文安全证明审查。

获取说明：paper-fetch MCP／CLI／Python 包不可用，未安装工具。普通 HTTP 最终取得真实出版社 PDF，人工验收结果单独记账，没有伪称 paper-fetch 工具成功。JZUS 的 PDF 端点及 HEP 两个补充材料链接发生 TLS／超时错误；补充材料内容未知，不能声称已排除其中包含代码。

## 2. 它在统一框架中负责什么

论文 §3 给出 Setup、Master_Keygen、Extract、Signature、Verification 五步，是完整 IBS 算法描述。适配时前两步归入 `IBSBackend.setup`；Extract 对应 `key_extract`，签名和验证分别对应 `sign`、`verify`，另补规范 `load_signature`。身份秘密通过 NTRU 陷门高斯原像获得；Extract 明确保存并复用同一身份的秘密。签名含拒绝采样，返回三个多项式对象。参见[原文 §3、算法 4—7](https://link.springer.com/content/pdf/10.1631/FITEE.1500197.pdf)。

困难假设记录为论文所定义的 **NTRU 格上的 SIS／γ-SVP**，不能改写成一般矩阵 SIS，也不能与普通 NTRU 加密假设不加区别。论文给出经典 ROM 下的存在不可伪造声明；本项目仍需核对通用组合定理要求，不能自动升级为强不可伪造、自我伪造防护或 QROM 结论。参见原文 §2.5、§4.2、§5。

## 3. 参数材料可用，但不能直接冻结为实现配置

原文印刷页 141 的表 2 含五组尺寸估算，均为 `N=512`。渲染图中 q 栏原样印为 `227 / 225 / 233 / 218 / 226`，k 栏为 `80 / 512 / 512 / 512 / 512`，λ 为 `28 / 14 / 14 / 14 / 14`。不要自行把 q 改读成 `2^27` 等幂，也不要把尺寸估算当实测性能或安全位数。[原表 2](https://link.springer.com/content/pdf/10.1631/FITEE.1500197.pdf)

本次发现必须在实现前澄清的具体差异：

1. §2.1.1 要求素数 q，而表中 `225/218/226` 不是素数。该表无法直接充当经过检查的数值参数包。
2. 算法 3 拒绝不可逆 f、g；算法 4 第 1 行却印为不属于可逆元素集合，同时末行计算 `h=g/f`。实现不能原样照抄这个冲突，应回到引用的生成算法核对并记录勘误依据。
3. 抽样宽度、基质量、有限尾误差、拒绝概率和重试预算尚需做同一配置的对应核验。本次没有完成参数搜索、攻击估计或真实采样。

这些是已观察到的文本／参数适配问题，不是已经完成的整篇安全否定结论。

## 4. 作者代码检索结果与可复用材料

检索范围包含准确标题、DOI、作者姓名和代码关键词，GitHub／GitLab／Gitee 定向搜索、期刊页面、补充材料链接与作者 ORCID 入口。**在这些已检查来源中没有确认 Xie 2016 IBS 的原作者实现或完整第三方复现。** 没有命中不等于代码不存在；补充材料尚未取得。同名的机器人研究者 Jia Xie 页面未认定为本文作者。

| 来源 | 已确认内容 | 在本项目中的用法 |
|---|---|---|
| [tprest/Lattice-IBE](https://github.com/tprest/Lattice-IBE) | Ducas–Lyubashevsky–Prest 2014 的作者 IBE 研究实现；含 NTRU 生成／采样等组件，依赖 C++、GMP、NTL；`License.eng.txt` 为 CeCILL 2.1 | 可作为 Xie 所引用上游的工程参考；它不是 Xie IBS，也没有两层 HIBE。不能直接复用参数当本 IBS 的安全配置 |
| [xff-github/NTRU](https://github.com/xff-github/NTRU) | [Tang 等 2021 身份基可链接环签名论文](https://onlinelibrary.wiley.com/doi/10.1155/2021/9992414)链接的 Java 项目，目录含 `Ntru.java`、`Ntru_ring.java` 等 | 是另一作者团队、另一种签名。仅作相关实现线索，未执行或验收，不冒充普通 IBS |

已将第一项固定提交 `7843ffbce2bfc19a123946c25809865392508f8c` 的原始 ZIP 存到仓库外交付区：

```text
C:/Users/A/.dsh/deliverables/NTRU-IBS-source-survey-2026-10-11/
  Lattice-IBE-7843ffbce2bfc19a123946c25809865392508f8c.zip
```

ZIP 33495 字节、19 个条目；SHA-256 `957d47624cddf1cd8982851785c92cd127d619ba0fb0fcab48b294d0c4f48f8f`。已清点，未执行。该版本 `params.h` 默认 `N0=512, q0=(1<<30)`；这是其自身 IBE 演示配置，作者 README 也限定为研究用途。[固定版本参数](https://github.com/tprest/Lattice-IBE/blob/7843ffbce2bfc19a123946c25809865392508f8c/params.h)

## 5. 接入工作与当前结论

可与其他原语并行完成：算法勘误表、NTRU 参数对象、标准编码／四类 IBS 对象、持久身份取钥、单体代数参考和统一 IBS 契约测试。真实签名链需补陷门生成、合法高斯采样、拒绝采样及其失败账本；已有 IBE 源码只解决其中可复用部分。

组合时 HIBE 不必与本 IBS 使用相同环或模数。应比较签名实际字节容量、参数版本、失败语义、身份与消息编码以及所选组合的理论前提；通过公共接口接 Hybrid／协议。候选加入清单不等于选定最终三套，也不等于后端可用。

当前：`security_claim=none`、`parameters_are_formal=false`、`implementation_admitted=false`；保留为 **NTRU IBS 原生算法候选**，与 BNN + Falcon 转换路线分别统计。
