# SRGG size attribution: dense matrices, ring representation and real objects

2026-10-18. Source paper: Jia, Liu, Tang and Wang, *Constructing Efficient Identity-Based Signatures on Lattices*, DOI `10.1049/ise2/6684889`. This correction uses frozen inputs, code and public receipts; it performs no new cryptographic execution. [Chinese report](report_zh-CN.md).

## Corrected conclusion

The statement **“SRGG requires 6.7–26.8 GB” does not describe the scheme's intrinsic size or the current backend's memory use**. It is a single full dense master-shape payload scenario for the historical conditional `n=512,w=8,d=2/3/4` candidates, assuming 64 bytes per entry. It is neither a key/signature size nor measured peak RSS, and it is not the published Table 4 `w=2` profile.

The same square ring operator has 512 times fewer coefficient slots. At the same assumed 64 bytes per coefficient, the master scenario is **13.1–52.4 MB**. The later structured, paper-joint and source-Schur backends already use ring polynomials, low-rank operators or small frequency matrices instead of the full dense coefficient expansion. Historical dense costs must not be used to reject the current implementation.

## Like-for-like accounting

An `L×L` operator over `QQ[X]/(X^n+1)` has `L²n` ring coefficients; its dense coefficient expansion has `L²n²` slots. Here `L=(2+w)d` for master geometry and `L=(2+w)d+1` for signature geometry. The slot ratio is exactly `n`, rather than a measured memory, runtime or communication improvement.

The following scenarios assume 64 bytes for either a dense entry or a ring coefficient. GB/MB are decimal; GiB/MiB are binary. Rational growth, interval precision, containers and concurrent workspaces are not bounded by this assumption.

| Historical w=8 rank | Master dense GB | Master ring MB (MiB) | Signature dense GB | Signature ring MB (MiB) |
|---:|---:|---:|---:|---:|
| 2 | 6.7108864 | 13.1072 (12.5) | 7.398752256 | 14.450688 (13.78125) |
| 3 | 15.0994944 | 29.4912 (28.125) | 16.122904576 | 31.490048 (30.03125) |
| 4 | 26.8435456 | 52.4288 (50) | 28.202500096 | 55.083008 (52.53125) |

The original [feasibility report](../2026-10-16-srgg-qualification/parameter-feasibility.md) already distinguishes the single-matrix scenario and ring coefficient ratio. Its table concerns signature geometry (7.4–28.2 GB), whereas 6.7–26.8 GB concerns master geometry. This addendum corrects broader summaries without rewriting frozen evidence.

For the published `n=512,w=2` rows, the same hypothetical full ring-square scenario is:

| Published row | Master ring MB | Signature ring MB |
|---|---:|---:|
| PARAM-I | 2.097152 | 2.654208 |
| PARAM-II | 4.718592 | 5.537792 |
| PARAM-III | 8.388608 | 9.469952 |

These remain distinct from actual RSS. Current implementations may retain low-rank witnesses and Schur pivots/gains instead of a full ring square, while temporary objects, interval arithmetic and rational growth add other costs.

## Existing measured serialized objects

These values come from the three frozen `param-*-bounded-final-lifecycle.json` [source-Schur receipts](../2026-10-18-srgg-source-schur/README_zh-CN.md). Each is one TEST-stream lifecycle, the default notation, a 5-byte identity and a 32-byte message; they are neither new runs nor averages.

| Row | Public JSON B | User-key JSON B | Master JSON B | Signature JSON B |
|---|---:|---:|---:|---:|
| PARAM-I | 34,522 | 84,190 | 102,682 | 35,334 |
| PARAM-II | 76,935 | 176,721 | 218,451 | 51,126 |
| PARAM-III | 136,604 | 303,760 | 377,733 | 67,112 |

The canonical user key embeds a hex-encoded public key and its tail. The master includes public data, witness and issued-key cache. These complete JSON objects therefore cannot be ranked directly against the paper's compressed coefficient components or C/rANS sizes. A separate frozen PARAM-I system-random run exists; it is not mixed into this table.

## Engineering changes and limits

1. Report coefficient counts, complete wire objects, execution time and peak RSS separately. Label the GB scenario as the historical dense representation.
2. Reuse the existing ring/frequency backends. Small exact geometry and source-Schur tests were rerun; sampler paths, parameters and guards were not modified.
3. For communication improvements, use a separately versioned compact codec with canonical parsing, key/identity binding, recovery and failure-state checks. Savings from JSON or embedded-public removal are distinct from the 512-fold slot ratio.
4. For RAM/time improvements, first measure process-tree RSS, preparation/extraction/signing time and cold/warm/cache boundaries under the same published profile. This package makes no new peak-memory or speedup claim.

The standard-library [calculator](../../../../experiments/research/candidates/srgg/representation_audit.py) checks historical matrix counts, emits both parameter families and measured object sizes, and binds inputs/source files by SHA-256. It allocates no large matrices and consumes no entropy:

```text
python -m experiments.research.candidates.srgg.representation_audit --output docs/research/team-b-delivery/2026-10-18-srgg-size-accounting/representation-audit.json
python -m experiments.research.candidates.srgg.representation_audit --output docs/research/team-b-delivery/2026-10-18-srgg-size-accounting/representation-audit.json --check
```

New scope tests: 8 passed. Existing geometry/source-Schur tests under the prescribed WSL Sage environment: 24 passed. Commands are recorded in [validation.json](validation.json). Existing sampler sources, parameters, receipts and manifests remain byte-identical. Metadata stays `security_claim=none`, `backend_admitted=false`, `parameters_are_formal=false`, `nist_security_category=null`. Representation accounting does not close other security/parameter questions; functional tests do not establish security.
