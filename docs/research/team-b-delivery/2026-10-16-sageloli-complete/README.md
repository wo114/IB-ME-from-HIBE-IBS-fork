# Shorter and Faster Identity-Based Signatures with Tight Security in the (Q)ROM from Lattices

**Authors:** Éric Sageloli, Pierre Pébereau, Pierrick Méaux, Céline Chevalier
**Affiliations:** Thales SIX; Sorbonne Université, CNRS, LIP6, PolSys; University of Luxembourg; DIENS, École Normale Supérieure, CNRS, Inria, PSL University; CRED, Université Paris-Panthéon-Assas.
**DOI:** `10.1007/978-3-031-33488-7_24`
**Frozen source:** HAL v1, `papers/2023_shorter_faster_ibs_sageloli.pdf`
**Source SHA-256:** `0e92f184828bc8643a774e9c334b14689346387981e766c311c596239ef73e3e`

## Abstract

We provide identity-based signature (IBS) schemes with tight security against adaptive adversaries, in the (classical or quantum) random oracle model (ROM or QROM), in both unstructured and structured lattices, based on the SIS or RSIS assumption. These signatures are short (of size independent of the message length). Our schemes build upon a work from Pan and Wagner (PQCrypto’21) and improve on it in several ways. First, we prove their transformation from non-adaptive to adaptive IBS in the QROM. Then, we simplify the parameters used and give concrete values. Finally, we simplify the signature scheme by using a non-homogeneous relation, which helps us reduce the size of the signature and get rid of one costly trapdoor delegation. On the whole, we get better security bounds, shorter signatures and faster algorithms.

---

This directory records the complete independent research implementation of the two Sageloli routes used by Team B:

- matrix SIS (`SISBackend`), and
- structured Ring-SIS (`RSISBackend`).

The implementation exposes `setup`, `key_extract`, `sign`, `verify`, and `load_signature`, strict v2 objects, fixed persistent issuing, restart recovery, bounded failure handling, and both mathematical routes' real full-dimensional delegation/signing samplers. It is an executable research baseline. It has **no security admission**: `security_claim="none"`, `backend_admitted=false`, and `parameters_are_formal=false`.

## Frozen implementation contract

The contract is in [`docs/specs/sageloli-ibs.md`](../../../specs/sageloli-ibs.md), with the paper-to-code source map in [`SOURCE_MAP.md`](SOURCE_MAP.md). The v2 wire magic is `IBME:SAGELOLI-IBS:v2`. v1 state is rejected and is never automatically migrated, rerolled, or reissued.

The default executable teaching points are:

| Route | Dimensions | Modulus | Identity width squared | Signature width squared |
|---|---|---:|---:|---:|
| SIS | `n=2,k=4,m=16` | `3^4=81` | `2^28` | `2^56` |
| RSIS | `d=4,k=9,l=22` | `3^9=19683` | `2^36` | `2^66` |

Widths use the paper density convention `exp(-π||x||²/s²)`. The fixed rounding width is `r²=16`. These points are intentionally small. Their public norms are vacuous and public linear solving can produce accepted signatures; this evidence is retained and is why no security category is claimed. The paper's two large RSIS points, `(k,d,l)=(65,2048,132)` and `(153,2048,308)`, are documented but have not been run here. The paper gives no concrete published SIS point, so none is invented.

## Paper correspondence and engineering choices

The root is built as `[Abar | G-Abar R]`, with CBD1 in the matrix route and the paper's four-block `4P_(1/2) × P_(1/2) × 4P_(1/2)` root distribution in the ring route. Because the paper prints both the negative public construction and `A[-T;I]=G`, v2 stores `R` and passes `T=-R` to the root sampler. A delegated identity key satisfies `A*T_id=H1-G`; signing passes that positive `T_id` to the same sampler interface.

SIS delegation makes `nk` full-dimensional calls. RSIS makes `k` coefficient-level calls and expands them through negacyclic rotations. The current numeric implementation uses global `SampleF` for SIS and block-Schur `SampleP`-style composition with block size `d` for RSIS. The paper has no separate `SampleP` pseudocode; this is a faithful interface-level interpretation, not a claim that MP12's continuous internal sampler has been reproduced bit-for-bit.

All finite rejection budgets are explicit. Uniform modulo-q mapping uses at most 192 trials per coefficient and a 64 MiB byte budget. Full sampler plans enforce the exact raw PSD admission before entropy. Numerical continuous tickets, finite precision, truncation and total statistical distance remain uncertified. `gamma^Sample` from the paper is therefore not copied into the implementation as an error certificate.

## Persistent issuer

`FixedIssuer` defaults to a 32-identity ledger, a 16 MiB object/state envelope, and a 300-second lock acquisition budget. It creates and fsyncs a pending marker, persists the pending identity, performs real sampling, atomically publishes the issued state, and removes the marker only after synchronization. Repeated identities return the same key after restart. Pending, failed, corruption, parameter mismatch, route mismatch, malformed wire, sampling failure, and persistence failure block automatic reissue. An optional expected public-key or parameter pin rejects a self-consistent state from another context.

The service intentionally fixes one identity key and its salt. Figure 1's `OSign` samples a fresh KeyExt and identity salt on each call; this service policy is therefore a documented model difference. Proposition 5's multi-signature distribution statement does not by itself close the ROM/QROM proof for this persistent service.

## Reproduction commands

The final test and runtime receipt is intentionally left for the integrating agent:

```text
`PYTHONPATH=src:. PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_sageloli_ibs.py tests/test_sageloli_sampling.py tests/test_sageloli_uniform.py tests/test_sageloli_service_recovery.py tests/test_sageloli_probe.py` → **144 passed, 0 failed, 0 skipped in 222.80 s** (WSL Ubuntu-24.04, Sage 10.9, Python 3.13.15). JUnit: `build/outputs/sageloli-complete-2026-10-16/sageloli-all.xml`; service recovery subset: 36 passed in 79.06 s; uniform subset: 53 passed in 0.53 s.
```

Run the repository's Sage environment and record the exact command, version, platform, repetition count, and result here after integration. Do not place seeds, private trapdoors, identity keys, signatures, or random tapes in this directory or in Git.

## Scope and remaining gaps

The lifecycle and attack tests are implementation evidence only. They do not prove SIS/RSIS hardness, the paper's ROM/QROM reduction, a fixed-service reduction, finite-sample total variation, formal parameter security, NIST equivalence, or any HIBE composition. Shared registry/CLI and combinations remain the coordinator's responsibility. The source map records every deliberate paper ambiguity and engineering deviation.
