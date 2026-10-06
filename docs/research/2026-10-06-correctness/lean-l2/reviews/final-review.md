# L2 集成源碼與假設獨立審查

日期：2026-10-06。Socrates 独立审查；末次状态由主代理根据其最终回报补录并统一复验。审查未修改证明代码。

## 1. 當前判定

**完整源碼鏈的數學陳述已核對：主定理針對真實 `DualSet` 的完整 Gaussian 無窮和，沒有把對偶分解、可和性、位移最大值或目標不等式改成新的最終假設。** `gaussianWeight_eq_euclidean` 排除了函數空間預設 sup 範數的混淆；`dualTheta_eq_nonzero_tsum` 精確扣除唯一零向量；η 使用正寬度可行集合的下確界，主定理只使用合法的單向上界。

**最终独立审计通过：Socrates 实际运行 `lake env lean Audit.lean`，exit 0，无警告或错误；113 个公开声明（87 个定理）的传递公理均限于 `propext`、`Classical.choice`、`Quot.sound`。** 主代理另以 `Verify.ps1` 完整构建、逐文件源码检查、公理审计和错误断言拒绝测试复验通过。此前的包装引理/import 问题已经解决，下文调试过程仅为历史记录。最终原始日志与全部当前文件指纹由交付包中的最新 `verification/run-*/verification.json` 固定。

本輪協調先指定四個模組的聲明審查，後將已寫出的 `DualMass`／`L2` 納入完整鏈審查；以上是本輪審查範圍的變更記錄，不把協調者的技術判斷改寫成人類使用者的直接引語。未修改證明代碼，未新建聊天／子智能體，未提交 Git，未下載 cache。

## 2. 證據範圍與固定環境

原數學對象與來源核對見同目錄 `math-review.md`：已核对指定正確性文件 §§2–4 L2，以及固定 MP12 PDF 第 10–13 頁。此處以該報告 B01–B11 為核驗清單，另行實讀集成源碼，不以先前紙面結論或協作者進度聲明替代本次檢查。

實測工具鏈：Lean `4.34.1`，commit `5045d0056413266e57c625dcd7c365b10e377c52`。Mathlib 源碼 HEAD：`d13f23b723b8a846827a245b89c10fc7d3f11612`；與 `lakefile.lean`、`lake-manifest.json` 一致。工作目錄為 `D:\Lean\projects\fooli-l2`，執行前只在目前 PowerShell 進程載入 `D:\Lean\Enter-Lean.ps1`。

前期用于声明审查的历史源码快照（后续增加接口和修复后的最终指纹见最新 verification.json，不把旧指纹误当最终版本）：

| 文件 | SHA-256 |
|---|---|
| `FooLiL2/MassBounds.lean` | `26B08F72258C24285B634DD43F016DD20AF83DE00573FBA487067C733CB21139` |
| `FooLiL2/ProductSum.lean` | `040F361C9A81D91D03A984E9933F417F612F88529F74270447B18E198E0F257D` |
| `FooLiL2/Gaussian.lean` | `606BDFF24E306CEAFA32A5C113088DBE21969CAE1BF046F420389409519978E8` |
| `FooLiL2/VectorGaussian.lean` | `7796B7EEBF4690CC8BA115157342DD9EA8357B01A787F7E14544C1211658F791` |
| `FooLiL2/Assembly.lean` | `79D32259AD020680B714B4AA6EBAC13F6FE80661FCCC9B389F1D144B42B34282` |
| `FooLiL2/Cosets.lean` | `64385A442C8010E4250ABE53556B2A5800DA850E50F0021FC3D1A27A435E0372` |
| `FooLiL2/DualMass.lean` | `01D960C2C8D63DE12F9D5BB353E6F29DE7DD307453EB20D86FBB30DBD8AA9BB0` |
| `FooLiL2/L2.lean` | `E1D99280F5B40CD2D76F7AAB571F9D6E3085F06BD731915BB8175C9BE84DE2A4` |

Cosets 加入素數域 import／包裝引理之前的快照為 `28EDF56D94920D2D0F09FF7C64670127DBDA02994B17B9F0DCD73C78652EE882`，它與上表版本不同。編譯結果須與具體版本相配。

## 3. 四個組裝模組的准确声明與前提

### 3.1 MassBounds

`finite_mass_extension_bound` 是有限非負權重的代數引理。它要求 `a≥0`、`r≥1`、`w≤m`、某一索引上的 `a=r^m`、逐項 `b≤r^w` 與 `∑a≤1+e`，結論為 `∑a*b−1≤2e+e²`。這些條件足夠；不需要额外的 `b≥0`，也不需要把 Gaussian 正寬度放進這一純代數層。

兩次乘法比較均有正確符號依據：`0≤∑a≤1+e`，以及 `r^w≤r^m=a_zero≤∑a`。`e≥0` 實際可由现有條件導出。`extensionError_pos`、`extensionError_lt_one` 另行使用 `0<e≤1/4`，沒有把有限質量界錯當成誤差參數自動小於 1。

`smoothingInf theta e = sInf {t | 0<t ∧ theta t≤e}`；`smoothingInf_le_of_mass_le` 明確提供成員 t 與下界 0，故 `csInf_le` 的使用充分。不需要先假設 inf 被達到，亦沒有聲稱 `η≤t ⇒ theta t≤e`。

### 3.2 ProductSum

`summable_fin_product` 和 `tsum_fin_product` 的輸入是每個一維函數的 `Summable` 及逐項非負性。無窮索引是真正的 `Fin d→ℤ`，不是截斷的整數盒子。歸納步透過 `Fin.consEquiv` 重索引，並顯式以 `mul_of_nonneg` 構造乘積族的可和性，再使用 `tsum_mul_tsum`。

這裡要求非負性比一般絕對可和乘積定理更強，但 Gaussian 的每一項為正，故不是 L2 的額外限制。d=0 時索引集合只有空向量，和與空乘積皆為 1；未發現零維遺漏。

### 3.3 VectorGaussian

`gridMass` 定義為有限個一維完整 Gaussian 質量的乘積。`gridMass_eq_gaussian_tsum` 在 `t>0` 下證出它等於

$$
\sum_{z\in\mathbb Z^d}\exp\left(-\pi t^2\sum_i(z_i+c_i)^2\right).
$$

因此沒有把乘積定義本身冒充多維格上的無窮和。`summable_grid_gaussian_exp` 額外給出這個指數形式的可和性；`gridMass_append` 明確處理 `Fin (m+w)` 的座標分塊。寬度單調與移位上界使用 Gaussian 已證定理，不把它們保留為外部假設。

此層全部使用座標平方和，沒有使用 `Fin d→ℝ` 的預設函數範數。`gridMass_append` 不要求 t>0 是合理的：該引理只關於有限乘積的代數分塊；要解釋為收斂的 Gaussian 和時，由相鄰定理的 t>0 提供條件。

### 3.4 Assembly

`coset_extension_bound`／`coset_l2` 仍是**有限索引的實位移族**定理。它們要求 `u zeroCoset=0`、`0<s≤t`、`w≤m`、`cosetTheta u s≤e`，再對 `coset_l2` 要求 `0<e≤1/4`。Gaussian 的可和性、位移上界、乘積與單調性都已在定理體中消解，不再由調用者提供 `ha0`／`hb` 等有限代數前提。

但這一抽象層没有假設索引陪集互不相交，也没有假設 `v zeroCoset=0`。其 `cosetTheta`、`extensionTheta` 是「按標籤計數的質量−1」，不能對任意輸入直接叫作真實對偶格的非零質量。這不是已聲明的數值不等式錯誤；語義辨識由 DualMass／L2 完成。

## 4. 三個特別核對點

### 4.1 Sup norm 陷阱已由具體等式排除

`DualMass.gaussianWeight` 定義為 `exp(−πt²∑i,x_i²)`。`gaussianWeight_eq_euclidean` 明確使用

```lean
‖WithLp.toLp 2 x‖ ^ 2
```

並調用 `EuclideanSpace.real_norm_sq_eq`，不是裸寫 `‖x‖`。因此它對應通常的 Euclidean Gaussian。例如 x=(1,1) 的平方範數是 2，而不是預設 sup 範數平方 1。

Cosets 中的 `Fin d→ℝ` 僅用來儲存座標，`DualSet` 的配對採標準 `dotProduct`，與此 Euclidean 結構一致。沒有以 sup 範數定義對偶或 Gaussian 權重。

### 4.2 sInf 單向使用正確，未偷加最小值結論

主定理先證 `dualTheta F t≤ε_F` 且 `t>0`，再對同一個真實質量函數套用 `smoothingInf_le_of_mass_le`。因此可行集合非空且以下界 0 有界，不借助實數空集 inf 的總化值。

源碼沒有建立 eta 的最小值存在性、達到性或反方向，也沒有在主定理內使用它們。這符合原 L2 的「給定 t 已平滑 ⇒ η≤t」方向。後續若僅保留數值 `η≤t` 再推端點平滑，應另證達到性或直接沿用当前已證的 Gaussian 質量界；不能把這種更強用法算成本次已完成。

零維情況不破壞当前定理：可行集合可能只有 inf 而無最小正元素，主定理仍只要求 inf 上界，沒有相反聲明。

### 4.3 零點扣除：抽象註解有邊界，真實主定理已接入證明

在 Assembly 的任意位移族中，`u zeroCoset=0` 不能保證擴展後含原點。具體取單元素索引，m=w=1、u=0、v=1/2、s=t=2，則總質量是

$$
g(2)h(2),\quad
g(2)=\sum_{k\in\mathbb Z}e^{-4\pi k^2},\quad
h(2)=\sum_{k\in\mathbb Z}e^{-4\pi(k+1/2)^2}.
$$

有 `0<g(2)−1<1/1000`、`h(2)≤2e^{-π}/(1−e^{-8π})<1/2`，故 `g(2)h(2)<1`。这些輸入甚至滿足 `coset_l2` 的小誤差假設，但 `extensionTheta<0`；實際擴展陪集不含零，其非零質量則為正。

因此 Assembly 行 48 的「explicit nonzero-mass bound」註解若脫離矩陣接入語境，有誤導可能。建議後續改成「indexed mass-minus-one bound」或明說需經 DualMass 接入。**這是註解／復用邊界，不是当前最終 L2 的阻斷。** 本任務不改源碼。

最終鏈已用三個實際步驟解決該邊界：

1. `dualMass` 的索引就是 `{y // y∈DualSet q C}`，不是任意陪集標籤。
2. `dualEquiv` 對整個有限模標籤×整數向量給出雙射，保證重索引不重複計數、也不漏掉 a=0 的非零整數點。
3. `dualTheta_eq_nonzero_tsum` 在已證 `Summable` 下，使用唯一零 subtype 元素及其權重 1，得到 `if y.val=0 then 0 else gaussianWeight t y.val` 的完整和。

因此主定理中的 `dualMass−1` 有真實的非零質量含義；沒有減掉整個 a=0 整數子格。

## 5. 完整数學鏈及 B01–B11

| 編號 | 源碼中的實際消解方式 | 聲明／語義審查判定 |
|---|---|---|
| B01 | `InKernel`、`qaryLattice`、`DualSet`；`gaussianWeight_eq_euclidean` | 整數模核、標準配對與 Euclidean 權重吻合；正寬度由 hs 及 hst 給出 |
| B02 | `FullRowRank` 就是模矩陣滿射；`matrix_surjective_iff_rank`／新增 `fullRowRank_iff_rank`；`fullRowRank_append` | 對 F 的滿射已證；素數秩版本需最新 import／包裝引理編譯完成 |
| B03 | `dual_subset_integerCosets`、`integerCoset_subset_dual`、`dual_eq_residueCosets`、標籤唯一性、`dualEquiv` | 正反包含、不交性與實際點集雙射均為已寫出的證明，不是新假設 |
| B04 | 一維 `summable_gaussian` → `summable_fin_product` → `summable_cosetParam_weight` → 經 `dualEquiv` 得 `summable_dual_weight` | 無窮重索引和乘積所需可和性有明確依賴鏈 |
| B05 | `residueCoset_zero` 保留整個整數格；`zero_mem_dualSet`、`dualTheta_eq_nonzero_tsum` 只扣零點 | 已消解；與只求 a≠0 的錯誤定義不同 |
| B06 | `gridMass_eq_gaussian_tsum`、`gridMass_append`、`shift_append`、`dualTheta_append_eq_extensionTheta` | 分塊索引、Euclidean 平方和及乘積質量的連接完整 |
| B07 | Gaussian 中 Jacobi theta 可和性、複 Poisson 公式、Fourier 和的範數比較、非零 prefactor 消去 | 位移最大值有完整證明體；主定理沒有接收它作假設 |
| B08 | `gaussianMass_antitone`／`gridMass_antitone`／`cosetTheta_antitone`；完整 a=0 質量與 `w≤m` 的冪比較 | s 處主質量前提先轉成 t 處界，未混同寬度 |
| B09 | `finite_mass_extension_bound` → `coset_extension_bound` → 真實 `dualTheta` 兩端改寫 → `l2_qary_mass_extension` | 最終結論已回到真實矩陣及對偶 Gaussian 質量 |
| B10 | `smoothingInf` 直接實例化為 `dualTheta q (appendMatrix A B)`；有成員及下界證明 | 只證此處所需的 inf 上界，沒有將一個任意 eta 函數作假設 |
| B11 | 沒有使用 min 或反方向 | 對当前 L2 不構成欠缺；不宣稱已證 MP12 一般非球形參數或標量 min 等價性 |

Cosets 的反向包含值得特別確認：先從真實對偶的配對條件推得 qy 是整數，再由 A 的模滿射構造整數右逆 D，並將 `x−D(Cx)` 送入模核，從而產生陪集座標。D、對偶分解及轉置單射都在證明內構造／證得，没有包成額外結構欄位或假設。`dualSet_eq_dualSubmodule` 又將該配對集合接到 Mathlib 的實對偶子模。

Gaussian 的主要分析輸入是 Mathlib 已證的 Jacobi theta／Poisson 求和定理。其唯一最終寬度假設為 t>0，位移 c 任意；沒有有限截斷、數值近似或把 Fourier 公式新增成 axiom。

## 6. 兩個主定理的最終前提帳本

`l2_qary_mass_extension`：

- `q : ℕ` 且 `[NeZero q]`；
- 整數矩陣 A、B，維度有限；
- `FullRowRank q A`，即模 q 線性映射滿射；
- `0<s≤t`、`w≤m`；
- 真實 `dualTheta q A s≤e`；
- `0<e≤1/4`。

輸出真實 `[A|B]` 的質量界、`0<2e+e²<1` 及對同一真實質量函數的 smoothingInf 上界。**唯一的主質量假設是原 L2 就要求的 Θ_A(s)≤ε₀；沒有直接假設 Θ_F 或任何難橋接。** 非零合數 q 的情形依賴的是滿射而不是域秩，屬於有效的一般化，不削弱素數版本。

`l2_prime_rank` 將前兩項改成 `[Fact q.Prime]` 與 `(modMatrix q A).rank=n`，再由素數域上的已證等價關係調用上述主定理。A、B 以整數提升呈現，不是更窄的矩陣輸入範圍：`liftMatrix` 與 `mod_liftMatrix` 給出任意 ZMod 矩陣的代表。

本形式化未構造 `IsZLattice` 離散／余緊類型類實例。這不妨礙本定理，因為它已對實際整數模核之標準對偶集合及收斂 Gaussian 和作精確聲明，也接到了 Mathlib dualSubmodule；若將來要調用需要這些類型類的其他定理，仍須建立相應實例。

實際 Setup 的 `AJ₀=G` 到 A 滿射、初始化好事件機率、SampleD 分布契約、L3/L4 尾界及安全歸約均不在 L2 命題本身的前提消解任務中。本次不得因此宣布整個 Foo–Li／IB-ME 正確性或安全性已完成。

## 7. 獨立編譯與公理依賴：目前已取得的證據

所有直接檢查均使用指定工作目錄中的 `lake env lean <路徑>`；未執行 update 或 cache 下載。

已獨立觀察到 exit 0：`MassBounds.lean`、`ProductSum.lean`、初版 `VectorGaussian.lean`、`DualMass.lean`。初次 `Assembly.lean` 檢查因尚無本地 `VectorGaussian.olean` 而未進入檢查，不能算作數學／Lean 證明失敗。

另外將 MassBounds、ProductSum、Gaussian、VectorGaussian、Assembly 的讀取內容只在記憶體內組合，移除它們互相之間的 import、保留並合併 Mathlib imports，透過 `lake env lean --stdin` 實際檢查；exit 0。這避免當時缺少本地 `.olean`，沒有建立額外檔案。以下十個宣告的 `#print axioms` 皆只回報

```text
[propext, Classical.choice, Quot.sound]
```

宣告包括 `extensionError_lt_one`、`finite_mass_extension_bound`、`smoothingInf_le_of_mass_le`、`summable_fin_product`、`tsum_fin_product`、`gaussianMass_le_zero`、`gridMass_eq_gaussian_tsum`、`gridMass_antitone`、`gridMass_le_zero`、`coset_l2`。

此記憶體聯合檢查不是最新全部模組的原始匯入鏈驗收：審查期間 VectorGaussian 加入了指數形式可和性及 append 引理，Cosets 亦加入素數域 import 與包裝引理。最終應以下節更新的完整鏈檢查為準。

曾實際取得的接入錯誤：

```text
FooLiL2\L2.lean:64:39: error(lean.unknownIdentifier):
Unknown identifier `fullRowRank_iff_rank`
```

当时源碼補入该引理后，曾因新增 import 暂停在：

```text
object file ...\Mathlib\Algebra\Field\ZMod.olean
of module Mathlib.Algebra.Field.ZMod does not exist
```

精確所需 import 已回報給主進程；這是依賴／集成狀態，不是把缺少的數學橋接視為可假設成立。

## 8. 完整鏈最終復核記錄

Socrates 最终回报：已经完成纸面推导、完整集成链的声明/假设/关键桥梁审查，且独立执行 `lake env lean Audit.lean` 得到 exit 0、零警告/错误。113 个公开声明、87 个定理；公理依赖仅为标准三项。该回报由主代理补录，原始可复验日志由主代理的统一 Verify 运行保存，不将回报冒充额外的原始日志文件。

主代理实际完整核验：全部九个本地证明/控制模块及入口逐文件从源码检查通过；四个主定理和关键语义桥接在 Audit 中显示真实前提；7 个精确控制定理通过；故意遗漏二次项的断言退出 1，错误为 `unsolved goals / False`，不是缺环境。源码无禁止的证明占位或额外公理，公开声明清单完整。最终日志还校验了 Lean 版本、9 项锁定依赖及核验前后文件哈希一致。

最终新增接口亦纳入核验：`dualSet_eq_of_modMatrix_eq`、`dualTheta_eq_of_modMatrix_eq` 保证整数提升不改变对象；`SmoothAt` / `smoothAt_iff_theta` / `l2_smoothAt` 保留直接质量证书；`l2_modular_matrices` 明确接收原始 ZMod 矩阵。没有用 eta 下确界的未证明反方向。

**最终判定：本包 L2 在明确原始前提下的数学陈述、真实对偶格/高斯桥梁及 Lean 机器检查均完成。** 不代表实际 Setup 前提已验证、采样器契约成立、L3/L4 已完成，或整个 Foo–Li/IB-ME 的正确性、安全性与性能已达标。
