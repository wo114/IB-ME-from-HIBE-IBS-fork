# Step22 — CHKP / Luo composition readiness

Date: 2026-10-11. Final run began 22:49:16 Asia/Shanghai (14:49:16 UTC).
Status: sidecar delivered; actual composition **WIP / blocked**.

## Exact first blocker

There is no `src/ibme/hibe/chkp.py` in the assigned worktree, nor another
complete CHKP public backend in the inspected `src/ibme/hibe` and
`experiments/research/first_suite` surfaces. Consequently there is no actual
CHKP object to supply to `HybridHIBE(inner_backend, ...)`. The first blocker is
`CHKP_PUBLIC_BACKEND_MISSING`, **before Setup, parameter execution, leaf
sampling, or a Luo signature operation**.

This is an implementation/interface blocker. The presence of `security_claim=none`
and `backend_admitted=false` is not used to reject a functional smoke. Security
admission and proof/parameter work remain with the main owner.

CHKP owner confirmation supplied through the user: step7 is current stable,
465 manifest entries pass, step8 and the formal `chkp.py` slot are absent, and no
real 32 B public backend is ready. This sidecar did not repeat the historical
465-entry audit or run the teaching collector.

## Current public surface

Source locations below are relative to the assigned worktree at
`C:/Users/A/.codex/worktrees/luo-acceptance-evidence/IB-ME-from-HIBE-IBS`.
The full public-name/signature inventory and SHA-256 values are in
`evidence/final/preflight.stdout.txt`.

| Surface / evidence location | What actually exists | What is absent or unsuitable |
|---|---|---|
| `src/ibme/hibe/api.py:117`, validator at `:103` | `setup`, `extract`, `derive`, `encrypt`, `decrypt`, `load_ciphertext`; separate public key-binding validator | Interface definitions do not provide a CHKP instance |
| `src/ibme/hibe/__init__.py:1` and `abb10.py:1` | Actual exports are Mock and teaching ABB10 | Neither can satisfy actual CHKP lineage, regardless of a renamed class or flag |
| `src/ibme/protocol/luo_hybrid.py:20`, `:35`, `:81` | Existing explicit Luo factory selects ABB10; parameter snapshot/decoders are ABB10-specific | Not a CHKP factory; changing only a backend name would misrepresent the implementation |
| `src/ibme/protocol/hybrid_hibe.py:123`, `:243`, `:305`, `:391` | Public param gate, identity encoder, generic adapter, seed-only inner encryption call | Requires real component loaders and a semantic binding validator from the primitive |
| `first_suite/identity.py:106`, `:193`, `:207` | `ROHIBEContext`, ordered paths, position-indexed G; 256 targets | Does not supply Setup, trapdoor/parameter admission or a complete HIBE object |
| `first_suite/leaf_state.py:109`, `:139`, `:168` | `FixedSeedKey` requires exactly 256 preimages; `FixedSeedState.resolve(sender, generate)` preserves fixed leaf state | Caller must supply the actual trusted sampler; accepting equations/counts cannot prove independence/distribution |
| `first_suite/delegation_state.py:149`, `:224` | `ReceiverState` / `MasterTreeState`, public issue/derive/state interfaces | Their callbacks and scope-bound loaders are not the frozen HIBE interface |
| `first_suite/seed_kem.py:45`, `:94`, `:125` | `SeedCapsule`; `encapsulate_seed(oracle, receiver, sender, seed, noise, *, rng=None)` and `decapsulate_seed(key, capsule)` | KEM functions, not an HIBE backend; wrong-path raw output requires outer authentication |
| `first_suite/root_generation.py`, finite sampler and compact delegation components | Separate root/sampling/delegation prerequisites | No public HIBE entry object, decoder bundle or actual Luo composition |

`first_suite/...` in this table abbreviates `experiments/research/first_suite/...`.
No private key field, trapdoor or private matrix was accessed by the sidecar.
Only public API calls, public configuration, source signatures and public test
fixtures were used. No key, preimage or seed was generated or saved.

The compact chain documentation (`docs/research/2026-10-11-first-suite-compact/README.md:9`,
`:29`, `:49`) explicitly calls its delegation an MP12 DelTrap pilot, reports n=1,
and says it is not the seven-entry backend. Those are inspected repository
records, not experiments rerun here. No claim of original-CHKP theorem coverage
or formal parameters is inferred from them.

## Exact input contract and the two capacity paths

Live calls to the current public Hybrid encoder gave:

- Raw `(receiver, sender) = (Bob, Alice)`, lengths 3 / 5 B.
- Encoded inner `(parent, child)` lengths **86 / 86 B** with roles P / C.
- The raw identity maximum is 64 B; a 65 B identity is rejected. The encoded
  identity width is always 86 B, not an instruction to pass an 86 B raw identity
  into the outer wrapper.
- The inner payload is a **32 B seed**, requiring 256 per-position preimages
  for the proposed CHKP bit construction. Identities are separate arguments.
- Outer application-message maximum in the current Luo profile is **3924 B**;
  the Hybrid payload limit is 65536 B. These are not inner seed capacities.

Step7's `a_contract/T4-contract-v0.4.md:57`, `:97`, `:137` specifies the current
same-leaf cap32 and disallows splitting one child over eight identity records.
One direct call to its public `serialize_sk2` per boundary rejected 33 and 256
vectors under that unchanged cap32 profile, with `SerializationError("invalid
leaf range")` (`wire_reference.py:265`). Zero-vector placeholders were used only
for rejection before any mathematical validation; they are not samples.

**Do not carry cap32 over to the newer repository component.** `first_suite`
already has 256-position representation and fixed state. This run checked its
256 public G inputs and its rejection of a 32-preimage key. It did not sample
256 preimages, prove their independence, or turn the component into a backend.
Position independence means independent sampling for distinct domain-separated
inputs; numerical target/output collisions do not justify retries or rejection.

The step7 collector `f_handoff/call_collector.py:275`, `:315` explicitly identifies
teaching ABB10. Its 216 B internal ABB10 framing must not become a CHKP seed size
or a count of 1728 CHKP preimages. It was inspected, not executed here.

## Minimal future patch plan — no implementation in this task

1. **CHKP owner provides one actual public primitive slot.** Implement or export
   the six frozen HIBE methods plus `validate_key_binding` in `src/ibme/hibe/chkp.py`.
   Map Setup to a real root/scope, Extract to fixed parent issue, Derive to one
   same-leaf 256-position generation, Encrypt/Decrypt to the actual seed KEM.
   A method facade around a fixture, no-noise diagnostic, or ABB10 is insufficient.
   Identify original CHKP versus a changed MP12 delegation profile explicitly.

2. **Freeze the public parameter and opaque wire contract.** Supply an explicit
   parameter object with `identity_bytes=86`, `max_message_bytes>=32`, full selected
   scope/profile and same-leaf capacity. Supply pk/msk/sk1/sk2 decoders, canonical
   `to_bytes` / bound `from_bytes(data)`, frozen identity properties and key/public
   binding checks. Scope-dependent `from_bytes(..., expected_scope=...)` needs a
   bound loader; simply handing that unbound method to Hybrid is insufficient.
   Preserve independent position sampling, same-address reuse and failure
   tombstones through serialization; never obtain 256 by combining eight identities.

3. **Main adds one explicit CHKP/Luo factory after that handoff.** In the protocol
   integration area, construct `HybridHIBE(actual_chkp, backend_id=distinct_id,
   public_key_type=..., master_type=..., level1_type=..., level2_type=...)`, then
   the existing Luo/BYTEAUTH composition. Keep `(rcv,phi)`, IDPAD, 32 B seed,
   HKDF/AAD and signature/envelope semantics. Existing `_ProfileDecoder` reads
   ABB10-specific public `.meta` fields and must not be reused as CHKP validation;
   add a small CHKP public snapshot/scope validator. No new registry is needed.
   Repository modifications and any profile/CLI wiring remain main/owner work.

4. **Run the source-bound preflight, then one bounded real smoke.** Exact source
   hash, selected algorithm/profile, public parameter snapshot and sampler lineage
   accompany it. Use Bob/Alice and a one-byte application message; record only
   lengths/counters and public lineage at inner calls (86/86/32). Confirm one
   full 256-position same-leaf generation, no identity sharding and no new draws
   on key reuse/restore. If any budget/format/validator gate fails, preserve the
   first failure and stop without a teaching fallback or resampling.

5. **Main subsequently completes composition acceptance.** Four identity
   combinations, signature/ciphertext edits, truncation/append/duplicate fields,
   random forgeries, same-parameter different-public-key binding, restoration and
   durable failure state need real combination evidence. Raw KEM wrong-path seed
   bytes must be rejected by Hybrid/BYTEAUTH. A matched small smoke alone would
   not close this gate. Proof and formal parameter admission stay separate.

These are concrete integration edits/obligations, not an implemented patch or
authorization to edit the CHKP owner's source. No owner was messaged.

## Checker behavior and validation

The preflight's default negative route needs only the Python standard library.
The public-contract probe additionally uses the existing installed cryptography
dependency through the repository. No installation, WSL process or Sage job was
started. The Windows runtime was Python 3.14.7, Windows 11 build 26200, 20 logical
CPUs; the read-only host query identified Intel Core Ultra 7 255HX. This is a
control/interface audit, not a performance measurement.

| Command, from the private sidecar | Final result |
|---|---|
| `python -B preflight.py` | exit **2**, exact first blocker `CHKP_PUBLIC_BACKEND_MISSING` |
| `python -B -m unittest -v test_preflight` | **26 passed**, exit 0; test elapsed 0.608 s |
| `python -B public_contract_probe.py` | **18 passed**, exit 0; preimages 0, encapsulations 0 |
| `python -B run_evidence.py --out evidence/final` | exit 0 means sidecar checks succeeded, including the expected blocked result |
| `git diff --check` on the input worktree | exit 0; no repository changes made by this sidecar |

Unit tests cover teaching/mocks, renamed teaching subclass, a false admitted flag
on a complete-looking unknown backend, direct ABB10 alias in a CHKP slot,
monkeypatched entry methods, wrong lengths/order, cap32, identity sharding,
repeated-preimage declarations, malformed/duplicate review fields, stale lineage,
and parallel unrelated changes. A decision-unit positive case establishes that
`none/false` does not prevent `READY_FOR_BOUNDED_SMOKE`; it is clearly a unit test
and not actual backend evidence. There was no real positive CHKP path available.

The checker is deliberately a **single-slot preparation tool**, not an automatic
recognizer of arbitrary cryptographic algorithms. A future main-reviewed source
record is required before candidate imports. It binds the inspected Python sources,
public method provenance and the explicit functional contract; it does not verify a
proof. An incorrect trusted review cannot be made correct by reflection or hashing.
No backend's own `backend_admitted=True` is trusted. Security output remains
none/false even when structural/functional prerequisites become ready.
The snapshot excludes native executables/external packages and runtime data;
their exact provenance must be recorded by the main review and actual smoke.

Initial `run-01` is preserved: 23 of 24 checker tests passed; the worktree-clean
assertion failed because parallel work added two Luo files. The checker was
corrected to record status and pin the real source snapshot. `run-02` passed
25 tests; final added the direct teaching-alias regression for 26. This is
transparent tool repair, not a CHKP cryptographic failure or a hidden retry.

## Lineage, files and remaining work

Input HEAD: `f079ce10fb6b3d2877465b308caaa30276d9e6f9`,
`test(luo): close single-primitive lifecycle evidence`.

Final source snapshot SHA-256:
`c49b98b93e04511e9fda1a9b13c5c28d66de09b0f54259d133b25d556055ffc9`.
It fingerprints 130 Python source files including the contemporaneous parallel
overlay. The per-file map is in the final preflight JSON. Changes from earlier
run fingerprints reflect ongoing parallel work; do not describe the repository
as globally frozen across the whole conversation.

Final before/after receipts compare **968 tracked repository files**, the source
snapshot, Git state, and the six relevant CHKP files read for this task. All
compared bytes/states are equal within that final run. This is not a repeated
full-package manifest audit. The following parallel-owned files were recorded
and preserved:

```text
?? experiments/research/luo_robust_abort_certificate.py
?? tests/test_luo_robust_abort_certificate.py
```

Delivered source files: `preflight.py`, `test_preflight.py`,
`public_contract_probe.py`, `run_evidence.py`, plus `README.md` and this report.
`evidence/final/environment.json` binds the four executable source hashes;
`evidence/final/manifest.json` hashes every receipt/output in that run. Previous
runs are retained under `evidence/run-01` and `evidence/run-02`.

No repository commit or push: all deliverables are outside the repository under
the explicitly authorized sidecar path. No `src`/`tests` repository files or
CHKP package files were edited. The preflight checker deliverable is complete;
actual CHKP composition, a real positive-path smoke, production decoder binding,
and formal proof/parameter admission remain unimplemented/unverified here.
