"""ABB prefix-valued public matrix hash engineering instantiation.

H itself is a matrix RO in the paper. A SHAKE bit tape feeding SampleR does
NOT inherit that indifferentiability claim. This implementation is explicit
engineering, has no private trapdoor, and returns a fixed matrix or ABORT.
"""

from hashlib import shake_256

from ibme.core.encoding import encode_bytes
from ibme.core.errors import EncodingError, RandomnessError
from ibme.core.types import validate_identity

DOMAIN = b"IBME:ABB-ROM:MATRIX-H:ENGINEERING:v1"
BLOCK_BYTES = 4096


def matrix_oracle_input(context, identities, *, identity_max_bytes):
    if not isinstance(context, bytes) or len(context) != 64:
        raise EncodingError("64-byte ABB public context required")
    if not isinstance(identities, tuple) or len(identities) not in (1, 2):
        raise EncodingError("ABB prefix has exactly one or two ordered identities")
    if type(identity_max_bytes) is not int or not 1 <= identity_max_bytes <= 256:
        raise EncodingError("bounded identity maximum required")
    checked = tuple(validate_identity(x, max_bytes=identity_max_bytes) for x in identities)
    return DOMAIN+encode_bytes(context)+len(checked).to_bytes(1,"big")+b"".join(encode_bytes(x) for x in checked)


class MatrixOracleTape:
    """Bounded public SHAKE blocks; independent role/path length framing.

    No TestRNG, seed reuse, incremental full-prefix digest or secret input.
    Block index is canonical uint64. No tape or mutable state enters a key.
    """
    def __init__(self, encoded_input, max_bytes):
        if not isinstance(encoded_input, bytes) or not encoded_input.startswith(DOMAIN) or len(encoded_input)>1024:
            raise EncodingError("bounded canonical public oracle input required")
        if type(max_bytes) is not int or not 0 <= max_bytes <= 2**44:
            raise RandomnessError("bounded public oracle byte budget required")
        self._input, self._max_bytes = encoded_input, max_bytes
        self._used, self._block = 0, b""
        self._block_number = -1

    @property
    def bytes_used(self):
        return self._used

    def read(self, count):
        if type(count) is not int or not 0 <= count <= 2**20 or self._used+count>self._max_bytes:
            raise RandomnessError("public oracle tape budget exceeded; no continuation")
        output = bytearray()
        remaining = count
        while remaining:
            number, offset = divmod(self._used, BLOCK_BYTES)
            if number != self._block_number:
                self._block = shake_256(self._input+number.to_bytes(8,"big")).digest(BLOCK_BYTES)
                self._block_number = number
            take = min(remaining, BLOCK_BYTES-offset)
            output.extend(self._block[offset:offset+take])
            self._used += take
            remaining -= take
        return bytes(output)


def prefix_matrix(context, identities, params, *, sampler=None):
    from .params import ABBROMParams
    from .primitives import MatrixSampleR
    from ibme.lattice.matrix_sampling import MatrixFiniteOptions
    if not isinstance(params, ABBROMParams):
        raise TypeError("independent ABBROMParams required")
    encoded = matrix_oracle_input(context, identities, identity_max_bytes=params.identity_max_bytes)
    options = MatrixFiniteOptions(tail_bits=params.finite_tail_bits,mass_bits=params.finite_mass_bits,
        precision_bits=params.finite_precision_bits,gaussian_abort_bits=params.finite_abort_bits,
        max_uniform_trials=params.uniform_trials,max_tape_bytes=params.max_tape_bytes)
    if sampler is None:
        sampler = MatrixSampleR(params.q,params.dimension,params.matrix_gaussian_squared_width,
            options=options,max_matrices=params.sample_r_max_matrices,max_tape_bytes=params.max_tape_bytes)
    if (type(sampler) is not MatrixSampleR or sampler.q != params.q or sampler.dimension != params.dimension or
            sampler.width_squared != params.matrix_gaussian_squared_width or
            sampler.max_matrices != params.sample_r_max_matrices or
            sampler.max_tape_bytes != params.max_tape_bytes or sampler.scalar.options != options):
        raise ValueError("public matrix oracle sampler differs from exact ABB profile")
    return sampler.sample(rng=MatrixOracleTape(encoded,sampler.random_tape_bytes)).rows
