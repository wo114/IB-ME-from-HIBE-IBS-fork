"""Public-only n=1 ABB bit recovery; a hardness negative control.

No private basis, preimage or RNG is an input. Enumerate the publicly bounded
first-coordinate error, reconstruct s, then filter every ciphertext coordinate
and both message phases. Return candidate counts/bits, not recovered s values.
"""

from ibme.core.errors import InvalidParameterError
from ibme.hibe.abb_rom import ABBBitPublic, ABBBitCiphertext


def recover_n1_bit(public, ciphertext, noise_radius):
    if not isinstance(public, ABBBitPublic) or not isinstance(ciphertext, ABBBitCiphertext):
        raise InvalidParameterError("public ABB bit inputs required")
    a = public.matrix
    if a.nrows != 1 or a.q != ciphertext.q or a.ncols != len(ciphertext.c1):
        raise InvalidParameterError("matching n=1 ABB public bit inputs required")
    if type(noise_radius) is not int or not 0 <= noise_radius <= 16384 or 4 * noise_radius >= a.q:
        raise InvalidParameterError("public attack radius outside finite resource profile")
    pivot = next((i for i, coefficient in enumerate(a.rows[0]) if coefficient), None)
    if pivot is None:
        raise InvalidParameterError("n=1 public matrix must have a nonzero column")
    inverse = pow(a.rows[0][pivot], -1, a.q)
    candidates, bits = 0, set()
    def small(value):
        value %= a.q
        return min(value, a.q - value) <= noise_radius
    for error in range(-noise_radius, noise_radius + 1):
        s = (ciphertext.c1[pivot] - error) * inverse % a.q
        if not all(small(c - coefficient * s) for c, coefficient in zip(ciphertext.c1, a.rows[0])):
            continue
        for bit in [0, 1]:
            if small(ciphertext.c0 - public.u0[0] * s - bit * (a.q // 2)):
                candidates += 1
                bits.add(bit)
    return {"public_error_combinations": 2 * noise_radius + 1, "candidate_pairs": candidates,
            "candidate_bits": sorted(bits), "private_inputs": False,
            "security_negative_control": True}
