# Complete issuer/signature/fault history: exact obligations and counterexamples

This is a derived audit of the standalone IBS implementation of Jia, Liu,
Tang and Wang, *Constructing Efficient Identity-Based Signatures on Lattices*.
The frozen source is `papers/2025_efficient_ibs_jia.pdf`, SHA-256
`258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`.
The paper does not define this persistent `FixedIssuer` or a disk-fault game;
the statements here are not attributed to its security theorems.  The original
Table 4 inputs and both explicitly labelled Gaussian readings are unchanged.

## Claim 1: conditional complete-state coupling

Consider two causal interactive machines with the same operation selector and
observation map.  Their state includes the root, all issued keys, pending/failed
entries, complete durable bytes and marker presence, backend/runtime state,
adversary state and view, and anything else able to influence a later
transition.  A public observation includes the returned key/signature bytes,
canonical snapshots if exposed, distinct errors and aborts, and any timing or
lock outcome the game elects to reveal.  The observation map must be identical
in both experiments; it cannot retrospectively hide a fault label.

Let initial complete-state TV be at most `alpha`.  Fix a measurable predicate
`Good` on a signing key and the complete state.  In the reference system let
the probability that *any* sign uses a key outside `Good` be at most `beta`,
including keys after restart, reload, or a permitted corruption.  For each
microtransition kind `j`, assume a pathwise cap `N_j` and a TV bound `delta_j`
on its **complete next-state and observation kernel** at every matching
reachable history before a bad-key sign.  Fault decisions interleaved inside
an issuance or signature are separate microtransitions unless the asserted
full-call kernel has already included their entire joint behavior.  Then

```
TV(complete histories) <= min(1, alpha + beta + sum_j N_j delta_j).
```

Proof: maximally couple initial states.  While complete histories match and
the reference has not entered the bad-key event, maximally couple the next
conditional kernels.  The probability of first divergence at a kind-`j`
step, conditional on a matching prefix, is at most `delta_j`; a path contains
at most `N_j` such steps.  Charge the reference bad-key event once, at its
first occurrence, regardless of later behavior.  The union bound gives the
displayed expression.  Common deterministic transitions cost zero *only if*
their complete inputs, exogenous schedule/fault decision and observation map
are equal.  Adaptive identities and messages require no independence between
queries, but source sampler claims still require their stated fresh iid bytes.

Pathwise replay of the same program, complete starting state, entropy tape,
fault/OS tape and schedule yields identical logical outputs.  This trivial
deterministic simulation does not couple the *distributions* of those tapes.
The arithmetic helper in `paper_fault_history_law.py` computes Claim 1 only
when all numerical premises are supplied; it explicitly does not certify any
of them for SRGG.

## Source correspondence and fault boundaries

`srgg_paper_service.FixedIssuer` inherits the storage lock and atomic-write
helpers from `srgg_service.FixedIssuer`.  For a new identity, its visible
program order is `_load` under `_locked`, check cache/capacity, `_begin`
(pending marker), persist pending snapshot, invoke `backend.key_extract` on
an issued-only working master, persist issued snapshot, `_finish` (remove
marker), then return the key.  If the body raises, it marks the in-memory
identity failed and calls best-effort `_block`; process exit can instead leave
the pending marker and snapshot.  Recovery rejects an existing marker,
failed snapshot, or pending entry.  Cached issued keys are returned without a
new extractor call.  `SourceSchurBackend.sign` is a separate backend method,
not a transaction of `FixedIssuer`; it has up to 64 attempts and preserves
norm retry, signature bytes, and a distinct exhaustion exception.  The
machine-readable source map records current SHA-256 and line anchors.

The observed tests for process exit, recovery, corrupt snapshots, and two
cooperating processes establish those tested functional paths.  They do not
assign a probability to disk errors, power loss, scheduler choices, lock
timeouts, timing observations, malicious rollback, partial writes, or faults
that interrupt a random draw.  `_block` intentionally catches failures of its
own repairs; therefore its success cannot be presumed under arbitrary faults.
The current fixed-root issuance bound is for the no-external-fault key kernel,
and it cannot be substituted for a complete fault-interleaved microkernel.

## Claim 2: the fixed-key signing result cannot close random-key signing

In an exact finite counterexample, both worlds issue the same uniform key in
`{0,...,N-1}`.  At fixture key zero both sign with the same deterministic
signature.  At every other key they return different signature atoms.  Thus
issuance TV is zero, fixture-key signing TV is zero, but complete
issue-then-sign TV is `(N-1)/N`, equal to `7/8` for the archived `N=8` witness.
This is a probability-logic counterexample, **not an SRGG forgery**.  It proves
that the predecessor's one frozen Alice key cannot serve as a uniform
conditional signing bound over keys output by a random issuance.

There is also an exact original-parameter object witness.  Under PARAM-I,
table-standard-deviation reading, use an all-zero CBD1 witness, zero 32-byte
public seed and its honest public relation.  Construct an Alice signing-key
tail with one coefficient `100000000` and the others zero.  The strict
`SigningKey` object serializes and round-trips because the current object
gate checks 256-bit coefficient size and algebraic reconstruction, not a key
norm.  For the original factor-one signature geometry, evaluating the shifted
Schur form on the corresponding coefficient basis gives a strictly negative
**exact rational** Rayleigh value in `fault-history-law.json`.  Hence not all
wire-valid keys have an admissible signing Schur plan.  This constructed key
is **not claimed to be output by Extract**.  It does not quantify bad-key
mass under the actual or mathematical issuance law; that mass remains null.

## Claim 3: unmodelled external faults can dominate TV

Let two worlds have exactly the same fault-free issuance and signing laws.
In one world, an externally injected read fault occurs with probability `p`
and is reported as a distinct atom; in the other it never occurs.  Complete
transcript TV is exactly `p`.  The archived example uses `p=1`, giving TV 1.
This is a logical counterexample, not an empirical disk-failure rate or an
attack on SRGG.  Fault-free TV cannot bound arbitrary faulty histories.

## Route limit and current conclusion

Route A was equal-tape pathwise replay; it proves only deterministic equality
under identical complete external inputs.  Route B was the adaptive
microtransition hybrid in Claim 1; the required all-root initial joint law,
random-key bad-event mass, and fault-interleaved conditional kernels are not
established.  Route C used Claims 2–3 and the original-parameter object
witness to reject shortcut composition.  The user permits at most two route
switches after the main route, so this audit stops here and records the full
history TV as `null` for all six Table 4 profile/readings.

For the *separate* fault-free fixed-root cases, the predecessor has at most
`2^-24` issuance-only logical history TV under the table-standard-deviation
reading, and at most `2^-18`, `2^-17`, `2^-17` for two adaptive sign calls on
one fixed Alice key for PARAM-I/II/III respectively.  Literal-density
issuance bounds remain null and its fixed-key two-sign bound is trivial `1`.
No column in that list can be added to another as a full-history bound.
All accepted Setup roots, norm-exhaustion probability, actual storage-fault
law, security reduction, native strong target, formal hardness and NIST
category remain separate unresolved conditions.
