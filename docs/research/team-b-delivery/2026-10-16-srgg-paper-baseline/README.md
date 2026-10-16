# Constructing Efficient Identity-Based Signatures on Lattices

**Authors:** Huiwen Jia, Ying Liu, Chunming Tang, Lin Wang.
**Affiliations:** Guangzhou University; Guangzhou Center for Applied Mathematics; Science and Technology on Communication Security Laboratory, Chengdu, China.
**Source:** IET Information Security (2025), [DOI 10.1049/ise2/6684889](https://doi.org/10.1049/ise2/6684889), CC BY.
**Original abstract:** In this work, we explore the recent developments related to lattice-based signature and preimage sampling, and specify a compact identity-based signature (IBS) on an ideal lattice for practical use. Specifically, we first propose an ellipsoid version of the G + G signature scheme (Asiacrypt 2023) that achieves slightly better signature size and higher security. Then, by adapting a specific preimage sampling algorithm to the modified G + G signature, we obtain an efficient IBS scheme. In addition, we prove its security in the quantum random oracle model (QROM), following the paradigm introduced by Zhangdry (Crypto 2012). Finally, a complete specification of the IBS, featuring three distinct parameter sets, is accompanied by a proof-of-concept implementation. We believe that the combination of the preimage sampling with the Fiat–Shamir transformation holds potential for application in the other advanced digital signature schemes.

## Actual delivery

2026-10-16. **The independent functional baseline at all three published inputs is complete; security admission is not.**
Six deterministic test lifecycles cover both Gaussian interpretations and all three profiles. An additional PARAM-I lifecycle uses SecureRandom.
Each issues one identity key, signs twice including after recovery, and passes 37 checks. Identity/message lengths are 5/32 bytes.
The test receipts contain **221 distinct passed cases, no failures or skips**: 128 new and 93 related regressions. Independent repeats are not added again.
Implementation commit: `e9736f28ba907be28ca0bf13a27b9e67187b0bab`; see [validation.json](validation.json).
Only local commits were made; no push or PR37 update.

All earlier optimization candidates, w8/r²64 inputs, factor-two investigations, conditional proofs and failures remain intact.
This implementation adds 13 source/test files and changes or deletes no preexisting tracked file.
[SOURCE_MAP.md](SOURCE_MAP.md) maps source pages, Tables 3/4 and Algorithms 1–8.

## Inputs, code and conventions

Retain `n=512,p=16383,b=31,w=2,Q=15744063,r≈1.16`, ranks 2/3/4, all four published widths and gamma.
The default `table-standard-deviation` uses shape `2πs²`; `literal-density-width` uses `s²`.
**The authors have not confirmed the default interpretation; r is rounded.** Objects bind the interpretation and cannot be interchanged.
Algorithm 6 leaves the integer lift of `e∈Z_p` unspecified: the implementation explicitly uses `centered-mod-p`, with `centered-mod-Q` HNF recovery.
It retains the literal factor one and adds no old raw/user norm caps or `Q>2γ` admission gate.

Separate modules in `experiments/research/candidates/srgg/`:

| Files | Responsibility |
|---|---|
| `paper_profiles.py`, `paper_parameters.py` | Published inputs, separately labelled author reports, bound conventions |
| `paper_algebra.py` | Exact ring equations, framed/domain-separated hashes, HNF and 2Q recovery |
| `paper_samplef.py` | Anisotropic joint Gaussian, rational ring square-root series, finite-error records |
| `paper_objects.py` | Strict public/master/user/signature objects |
| `paper_backend.py` | setup/key_extract/sign/verify/load_signature |
| `paper_validation.py`, `paper_audit.py` | Executable lifecycle, malformed-input and substitution checks |
| `src/ibme/ibs/srgg_paper_service.py` | Persistent fixed issuance, default one-user capacity, explicit lock timeout |

Four `tests/test_srgg_paper_*.py` files validate these modules; validation.json lists every changed path.
The independent interface is implemented. Shared registration/CLI, HIBE combinations and security admission remain integration work.

## Reproduction and measurements

```bash
# From the repository root inside WSL; use the existing designated Sage env.
export PYTHONPATH=src:.
~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_audit --profile PARAM-I --output build/outputs/paper-PARAM-I.json
# Repeat with PARAM-II / PARAM-III; add --interpretation literal-density-width
# for notation sensitivity, or --production-random for OS entropy.
~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_profiles.py tests/test_srgg_paper_samplef.py tests/test_srgg_paper_backend.py tests/test_srgg_structured_geometry.py tests/test_srgg_algebra.py tests/test_srgg_wide_scalar.py
~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_service.py
```

Measured under WSL2, Sage 10.9, Python 3.13.15 on an Intel Core Ultra 7 255HX, 20 cores/20 logical processors, 33676681216 bytes RAM.
Framed SHAKE256 hashes are modelled in the ROM. Fixed randomness is test-only; the default backend uses OS-backed SecureRandom.
One lifecycle per parameter point is not a statistical benchmark. Concurrent work was running during these measurements.
Default-interpretation deterministic runs:

| Profile | Setup s | Extract s | Sign s | Sign after recovery s | JSON signature bytes | Successful replacements |
|---|---:|---:|---:|---:|---:|---:|
| PARAM-I | 1.25 | 42.22 | 28.82 | 29.12 | 35423 | 0 |
| PARAM-II | 2.84 | 56.44 | 17.00 | 32.80 | 51144 | 1 |
| PARAM-III | 5.14 | 90.93 | 39.61 | 22.14 | 67219 | 1 |

The SecureRandom PARAM-I program peaked at 230512 KiB RSS (about 225.1 MiB); only that run has a peak-RSS measurement.
[Resource receipt](PARAM-I-secure.resources.txt) replaces the machine-specific Sage home path with `~`.
The authors' C/gcc8.3/ANS sizes and medians over 1000 cycle measurements remain labelled `published_inputs.author_report`; no ANS or C-performance reproduction is claimed.

Tests include entropy-free fixed-key reuse, independent-process recovery, two-process concurrent issuance, exit after pending commit, four issuance/write faults, damaged-state preservation, wrong public/parameter rejection, strict four-object parsing, and identity/message binding.
Each profile also has 32 random-forgery negative controls. Zero-witness algebra fixtures are explicitly separated from genuine Gaussian lifecycles.
State is trusted local plaintext. WSL process/file tests do not guarantee hard-power-loss recovery, malicious rollback resistance, or mixed native-Windows/WSL writes.

## Preserved attacks and unresolved conditions

**Real PARAM-II/III signatures admitted same-message replacements.** Shifting a coefficient in the first identity block by ±Q leaves the commitment unchanged modulo 2Q; the replacement verifies when it remains within the original gamma.
The default PARAM-I sample had no eligible candidate; this is not a proof of resistance. All three density-interpretation runs found replacements.
This rules out a native-strong claim for this implementation. The attack is not a fresh-message forgery and does not directly refute the paper's ordinary EUF-CMA result; other theorem-to-code obligations remain separate.
Each `native_strong_probe` records the outcome without exporting signatures or secrets.

The actual coarse SampleF error bounds remain visible: default PARAM-I/II totals are about `2^-15`; PARAM-III master is about `2^-14`, while its signature's public bound is **1**.
The latter includes a trivialized numerical bound and does not certify high-precision sampling. All density-interpretation total bounds are **1**.
These are upper bounds, not measured distances or failure probabilities; they do not certify the paper's epsilon or high-query budget.
The ζζ*=2 versus factor-one issue, HNF/FS distribution and QROM applicability remain unresolved.
Both initial unsigned-remainder failure receipts are retained; they diagnose an implementation choice and do not prove the published parameters invalid.

Claims remain `security_claim=none`, `backend_admitted=false`, `parameters_are_formal=false`, `nist_security_category=null`.
Kyber/ML-KEM/NIST are future comparison targets. Tests are not security proofs. Complete security reduction, formal parameter admission, and original ANS/C reproduction are not completed deliverables.
MANIFEST.json pins all delivery files. [Chinese version](README_zh-CN.md).
