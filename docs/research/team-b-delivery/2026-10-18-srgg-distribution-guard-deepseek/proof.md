# SRGG guarded distribution audit: current implementation and conditional scope

Revision: 2026-10-19. This replaces the contradictory v3 heading/body scope.
It records the current service policy and existing numerical comparisons; it
adds no security proof, algorithm variant or cryptographic parameter search.

Primary source: Jia, Liu, Tang and Wang, *Constructing Efficient Identity-Based
Signatures on Lattices*, IET Information Security (2025),
[DOI 10.1049/ise2/6684889](https://doi.org/10.1049/ise2/6684889).
Frozen PDF `papers/2025_efficient_ibs_jia.pdf`, SHA-256
`258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`.
The original Table 4 parameters remain
`n=512,p=16383,b=31,w=2,q=961,Q=15744063,d=2/3/4`, with the existing
`table-standard-deviation` and `literal-density-width` interpretations.
There is no HIBE content. Project security working assumptions are not new
verification results; all safety fields stay none/false/false/null.

## 1. Current code and historical versions

The default `paper_schur_backend.SourceSchurBackend` executes the complete
Setup and signing audit gates. The default persistent issuer uses it.
`src/ibme/ibs/srgg_paper/guarded.py` provides a compatibility alias to the same
backend; it does not stack an additional sampler or audit pass. Constructors
and gate checks share the documented failure policy: an operational Setup gate
failure rejects/retries the root; signing failure aborts the fixed key without
re-extracting or replacing it. Arbitrary programming/runtime exceptions are not
silently reclassified into probabilistic root rejection.

References below to an unguarded backend denote historical source revisions.
There is no current hidden unguarded probe: a stopped legacy probe is not an
empty-search result. The guard changes service acceptance/abort policy, while
the paper's widths, distribution formulas and signature equations stay fixed.

| Event | Definition |
|---|---|
| `A` | paper's exact positivity condition `Sigma_p-r^2 I > 0` |
| `G_C` | mathematical condition `C > 64 I` |
| `B_legacy` | historical unguarded finite-preparation success |
| `H_setup` | current complete implemented master preparation/audit/source/C/object predicates |
| `H_sign` | current complete implemented signing preparation/audit/source predicates |

In the older v3 body, `G` meant the audit predicate while another package used
`G` for `C>64I`. This revision uses the explicit names above throughout.
Interval soundness gives `B_legacy subset A` and
`H_setup subset G_C subset A`. No completeness claim in the opposite direction
is implied by sound intervals or passing deterministic witnesses.

## 2. Why the numerical comparisons are gate-uniform

The finite/convolution/normalizer/issuance/sign formulas use only:

- the ideal Schur floor 64;
- gain/stored-factor covariance error gates `2^-128` and center error `2^-96`;
- factor envelope `(2,2^32)`, center envelope `<2^240`, finite output guards;
- the fixed `B=512`, `P=768`, dyadic windows and scalar/entropy certificates;
- original dimensions and `r^2`.

Actual pivot/gain values are used to verify the gates, not as free numerical
inputs to these comparison formulas. The six deterministic roots and a second
accepted-root check are witnesses for the implemented gate set. They do not
estimate the probability of Setup, signing acceptance or failures.

The retained finite-chain expression is

```text
lower_batch + rounding_batch + leaves*(n/2)*2^-170
+ leaves*2*n*(2^-6000+delta_stored)
+ leaves*4096*n*(2^-96+delta_ideal),
delta_stored = n*2^32*(2^-168+2^-490)+2^-400,
delta_ideal = delta_stored+n*32*2^-128.
```

The convolution and normalizer calculations use the floor 64; the issuance
comparison adds the existing root-independent gadget digit and completed-square
terms; the sign-call comparison adds the existing `u` batch and multiplies by
the unchanged 64-attempt cap. No numerical formulas are changed in this repair.

| Profile | Reading | master joint | signature joint | first issuance | issuance-only capacity history | one sign call |
|---|---|---:|---:|---:|---:|---:|
| I | std | `2^-26` | `2^-25` | `2^-25` | `2^-24` (3 ids) | `2^-19` |
| II | std | `2^-25` | `2^-24` | `2^-25` | `2^-24` (2 ids) | `2^-18` |
| III | std | `2^-25` | `2^-24` | `2^-24` | `2^-24` (1 id) | `2^-18` |
| I | literal | `0.6781...` | `0.8964...` | null | null | `1` |
| II | literal | `0.8173...` | `0.9666...` | null | null | `1` |
| III | literal | `0.8964...` | `0.9893...` | null | null | `1` |

All rows are conditional on the complete applicable gates actually passing,
fresh independent uniform bytes and the stated exception-free MPFR arithmetic
model. Abort is retained as an output atom. Literal-density issuance remains
null because the gadget normalizer sufficient gate fails. The literal signing
bound is the trivial 1, not a small composition error.

## 3. Mathematical good-root bounds are a separate result

The related [distribution-chain note](../2026-10-18-srgg-distribution-chain/proof.md)
retains the exact identities `G_C subset A` and ideal Schur floor `L2>64`.
Existing CBD1 trace moments give `mu(G_C^c)<=q_C`, the mathematical conditioned
root-law bound `q_C/(1-q_A)`, and `q_C^64` for independent mathematical G_C
retries. These do not close actual implemented rejection probabilities.

A uniform finite-preparation enclosure has not been supplied. In particular,
the current 192-bit C gate can be inconclusive near the exact boundary 64;
no shell-width/probability correction is certified. The candidate envelope
constants and boundary probes cannot establish `G_C subset B_legacy` or a
corresponding implemented acceptance budget. Both `B_legacy` and `H_setup`
acceptance-law comparisons with the paper's `mu(.|A)`, the C-gate shell mass,
current gate rejection mass and the actual 64-attempt Setup abort remain null.
The repair to retry gate failures is control-flow correctness, not a new bound
on how often they fail.

## 4. Random-issued keys with the same signing guard

Let `P_K` and `Q_K` be the existing actual and ideal first-issuance
key-plus-abort laws on an applicable accepted root, with distance at most
`delta_issue`. Run the same deterministic signing predicate on both. Bad keys
have the same logical abort behavior; on good keys use the uniform signing
kernel error `epsilon_good`. The retained conditional comparison is

```text
TV(guarded issue + s adaptive signs) <= min(1,delta_issue+s epsilon_good).
```

This data-processing statement needs no separate `beta_bad` term. The old
unguarded bad-key mass is still strictly positive and unquantified: the
canonical large-tail key remains in the reference support and fails its
signing Schur condition. Its observed support obstruction is preserved.
If key bytes are returned before signing, they remain in both transcript
models; a post-issuance guard cannot erase that output on only one side.

Under the std reading the dyadic issue+1-sign bounds are
`2^-19/2^-18/2^-18` and issue+2-sign bounds are `2^-18/2^-17/2^-17`.
Literal-density combinations remain null because issuance is null. Both
reference and implementation use the same 64 norm attempts and abort outcome;
standalone norm-exhaustion probability is not estimated here.

## 5. Logical history scope only

The history scope is logical API outputs plus deterministic persistent state:
canonical issued keys/signatures, pending/failed/issued state, snapshots,
cached returns and matched logical error labels. Use matching logical
schedules, common guard/abort semantics and the same initial Setup law, or
explicitly condition both sides on the same successful Setup/root. The
conditional output-kernel hybrid then uses section 4; new identities pay
issuance once, while cached repeats add no new sampling cost.

Wall-clock timing, lock scheduling, entropy consumption and internal
sampler/runtime traces are excluded. The output-kernel estimates do not
establish a joint law for these observables. In particular the prior v3 body
that included "any timing/lock outcome" exceeded the available evidence.
The actual complete-service history including a comparison of its Setup law
remains null; no mathematical `q_C` value silently supplies that missing cost.

No disk/process/rollback/power fault probability model is defined. An injected
read fault of probability p can cause transcript TV p despite identical
fault-free output laws. Faulty histories therefore remain null.

## 6. Evidence and implementation limits

The relevant tests cover gate control flow, fixed identity behavior and
conditional numerical recombination. Frozen receipts bind the exact code and
test environment used; their deterministic roots are not random acceptance
samples. A disabled historical unguarded search must be reported as disabled,
not as evidence that `B_legacy minus H_setup` is empty.

The earlier compact-codec sizes/times/RSS used a different frozen backend
without the current default guard. They do not become measurements of this
service by changing metadata or importing the same codec. New guarded resource
measurements, if required, must be a separate experiment.

Open implementation/parameter correspondence items retain their previous
status: author SampleZ/C correspondence, source notation ambiguities,
native-strong observations, structural hardness, formal parameter admission
and NIST category. This repair introduces no supplemental security proof task.

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q \
  tests/test_srgg_paper_distribution_guard.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m \
  experiments.research.candidates.srgg.paper_distribution_guard \
  --output build/deepseek-distribution-guard-new.json
```

Output must not exist. See [validation.json](validation.json),
[distribution-guard.json](distribution-guard.json) and the verifier for
fixed hashes, exact reported values and the actual reproduction environment.
The historical environment was WSL Sage 10.9 / Python 3.13.15. Functional tests,
source hashes and finite TV estimates do not establish an IBS security proof.
