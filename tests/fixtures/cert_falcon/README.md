# Official Falcon v1.2 round-3 TEST vectors

`round3.json.gz` reduces all 100 Falcon-512 and all 100 Falcon-1024 cases from
the authors' [round-3 submission](https://falcon-sign.info/falcon-round3.zip).
Archive SHA-256: `d625407dbda9e5835f610aaeba1147e029988a6610e0107dfd292033138e1d47`.
The embedded manifest pins both original response files. Gzip SHA-256:
`4e70a06b5d74cdf9a93f0ca58dde6c009eac54d83e5ce5c42755195d1bb954b1`.

Reproduce with `python -m experiments.research.certified_falcon_vectors
<archive> tests/fixtures/cert_falcon/round3.json.gz` (requires cryptography).
The generator implements the submission's AES256 CTR-DRBG for **TEST** seeds
only, extracts the three independent keygen/nonce/signing inputs, and records
SHA-256 of the published keys/signature. No real private material is included.
The full original KAT's private keys are public test vectors, not production
secrets. Each test regenerates and compares both keys and the exact compressed
signature before verifying it and checking a changed message.

199 signatures also fit the fixed padded representation byte-for-byte. One
official compressed signature is too long: the separate padded replay must
actually resample, preserve its nonce and verify, rather than truncate it or
skip the case. Compressed KAT output is available only in the separately built
vector driver; the IBS provider accepts padded signatures exclusively.

These are Falcon v1.2 vectors, not FN-DSA/FIPS 206 vectors. Base-source MIT
notices are retained in the vendored authors' files. Public vector reduction
and fixture generation are test material and confer no IBS security admission.
