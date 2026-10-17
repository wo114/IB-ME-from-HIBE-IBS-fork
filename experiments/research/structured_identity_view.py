"""Public identity-preamble normal form and its existing n2 negative control.

This is a standard LWE normal form, already supported by the estimator.
It identifies two truly fresh H blocks as the ciphertext sample source.
The probe reads exactly a public key and ciphertext, never a private key.
"""

import argparse
from hashlib import sha256
from itertools import product
import json
from pathlib import Path
from unittest.mock import patch


def identity_noise_view(root_rows, leaf_rows, preamble, q):
    """Return H and b_H = c_H-H^T*c_I = H^T*(-e_I)+e_H mod q."""
    if type(q) is not int or not 3 <= q <= 2**256-1:
        raise ValueError("exact modulus required")
    if (not isinstance(root_rows, (tuple, list)) or not root_rows or
            not isinstance(root_rows[0], (tuple, list))):
        raise ValueError("finite public root rows required")
    n, m = len(root_rows), len(root_rows[0])
    if not 1 <= n <= m <= 65536 or n > 4096 or n*m > 2**20:
        raise ValueError("public-view dimension budget")
    if (not isinstance(leaf_rows, (tuple, list)) or len(leaf_rows) != n
            or not isinstance(preamble, (tuple, list)) or len(preamble) != 3*m):
        raise ValueError("complete two-H-block preamble required")
    for rows, width in ((root_rows, m), (leaf_rows, 3*m)):
        for row in rows:
            if (not isinstance(row, (tuple, list)) or len(row) != width or
                    any(type(x) is not int or not 0 <= x < q for x in row)):
                raise ValueError("canonical public residues required")
    if any(type(x) is not int or not 0 <= x < q for x in preamble):
        raise ValueError("canonical preamble residues required")
    if any(root_rows[i][j] != int(i == j) for i in range(n) for j in range(n)):
        raise ValueError("the public root must actually start with I")
    if any(tuple(a) != tuple(b[:m]) for a,b in zip(root_rows, leaf_rows)):
        raise ValueError("leaf does not extend this public root")
    h = tuple(tuple(row[m:]) for row in leaf_rows)
    b = tuple((preamble[m+j]-sum(h[i][j]*preamble[i] for i in range(n))) % q
              for j in range(2*m))
    return h, b


def public_negative_control(public_file, ciphertext_file):
    from ibme.core.randomness import SecureRandom
    from ibme.hibe.mp12_structured import StructuredPublicKey, StructuredCiphertext
    from ibme.lattice.matrix_sampling import mp12_structured as tool
    from ibme.lattice.chkp.joint_parameters import ceil_sqrt
    def forbidden(*args, **kwargs):
        raise AssertionError("public negative control requested a root, sample or entropy")
    reads = []
    def read(path, role):
        reads.append(role)
        return path.read_bytes()
    with patch.object(SecureRandom, "read", forbidden), \
            patch.object(tool, "generate_structured_root", forbidden), \
            patch.object(tool.StructuredPreimageSampler, "__init__", forbidden):
        raw_public = read(public_file, "public_key")
        raw_ct = read(ciphertext_file, "ciphertext")
        public = StructuredPublicKey.from_bytes(raw_public)
        ciphertext = StructuredCiphertext.from_bytes(raw_ct)
        p, ct = public.params, ciphertext.capsule
        if p.n != 2 or ct.context != public.context or ct.q != p.q:
            raise ValueError("the original matching-context n2 research object is required")
        receiver, sender = b"B"*86, b"A"*86
        h, b = identity_noise_view(public.oracle.root_rows,
            public.oracle.leaf_rows(receiver, sender), ct.preamble, p.q)
        radius = ceil_sqrt(p.q_alpha**2*129)
        count = (2*radius+1)**p.n
        if count > 100000 or 4*radius >= p.q:
            raise ValueError("bounded public n2 negative-control domain exceeded")
        targets = public.oracle.targets(receiver, sender)
        def centered(x):
            x %= p.q
            return x-p.q if x > p.q//2 else x
        survivors, recovered = 0, set()
        for leading_error in product(range(-radius, radius+1), repeat=p.n):
            z = tuple(-x for x in leading_error)
            if any(abs(centered(b[j]-sum(h[i][j]*z[i] for i in range(p.n)))) > radius
                   for j in range(2*p.m)):
                continue
            survivors += 1
            secret = tuple((ct.preamble[i]+z[i]) % p.q for i in range(p.n))
            bits = []
            for target, terminal in zip(targets, ct.terminals):
                value = terminal-sum(a*s for a,s in zip(target, secret))
                choices = [bit for bit in (0, 1)
                           if abs(centered(value-bit*(p.q//2))) <= radius]
                if len(choices) != 1:
                    break
                bits.append(choices[0])
            if len(bits) == 256:
                seed = bytes(sum(bits[8*i+j] << (7-j) for j in range(8)) for i in range(32))
                recovered.add(sha256(seed).hexdigest())
        expected = sha256(bytes(range(32))).hexdigest()
        if expected not in recovered:
            raise AssertionError("original public n2 message was not recovered")
    return dict(schema="STRUCTURED-IDENTITY-NORMAL-FORM-NEGATIVE-CONTROL/1", status="passed",
        parameters=p.record(), matching_identity_bytes=86, message_bytes=32,
        public_key_sha256=sha256(raw_public).hexdigest(), ciphertext_sha256=sha256(raw_ct).hexdigest(),
        input_roles_read=reads, private_inputs_read=0, new_roots=0, new_keys=0,
        sampler_calls=0, entropy_reads=0, candidate_tuples=count,
        H_samples_used=2*p.m, root_other_columns_used_for_candidate_filter=False,
        surviving_H_secret_candidates=survivors, recovered_seed_sha256=sorted(recovered),
        original_seed_recovered=True, finite_noise_radius=radius,
        minus_leading_error_and_encryption_secret_not_published=True,
        repetitions=1, uses_ROM=True, new_attack_principle_claimed=False,
        security_claim="none", backend_admitted=False, parameters_are_formal=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-file", type=Path, required=True)
    parser.add_argument("--ciphertext-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists(): raise ValueError("new public receipt required")
    report = public_negative_control(args.public_file, args.ciphertext_file)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(report, indent=2)+"\n")
    print(json.dumps(dict(status="passed", candidates=report["candidate_tuples"],
        survivors=report["surviving_H_secret_candidates"], original_seed_recovered=True)))


if __name__ == "__main__": main()
