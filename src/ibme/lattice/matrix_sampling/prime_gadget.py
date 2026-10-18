"""Bounded prime-q gadget sampling with a single public k-square basis.

This A3 tool admits q up to 256 bits independently of HIBE wire/trapdoor
limits. It samples the complete product coset using the existing finite GPV
engine; no root, delegation or secret basis is constructed. Coordinates are
row-major blocks. The default binary convention is preserved; an explicit
power-of-two radix uses MP12 Theorem 4.1 with a different public certificate.
"""

from itertools import islice

from sage.all import QQ, ZZ, matrix

from ibme.core.randomness import SecureRandom
from ibme.lattice.chkp.basis import KernelBasis, ModMatrixReference
from ibme.lattice.chkp.entropy import CheckedEntropy
from .gpv import MatrixFiniteGPV
from .scalar import MatrixFiniteOptions, exact_integer


VERSION = "IBME/PRIME-BINARY-GADGET/1"
RADIX_VERSION = "IBME/PRIME-RADIX-GADGET/1"
MAX_MODULUS_BITS = 256
MAX_ROWS = 16384
MAX_OUTPUT_COORDINATES = 2**20


def _modulus(q):
    q = exact_integer(q, "public binary gadget q", minimum=3,
                      maximum=2**MAX_MODULUS_BITS-1)
    if q % 2 == 0 or not ZZ(q).is_prime(proof=True):
        raise ValueError("public binary gadget requires a proven odd prime")
    return q


def radix_geometry(q, radix_bits=1):
    """Exact bounded radix geometry; no matrix, sample or private state."""
    q = _modulus(q)
    bits = exact_integer(radix_bits, "power-of-two radix bits", minimum=1, maximum=32)
    return q, bits, 1 << bits, ((q-1).bit_length()+bits-1)//bits


def prime_gadget_kernel(q, *, radix_bits=1):
    """Certify the COMPLETE kernel of (1,b,...,b^(k-1)) modulo q.

    Consecutive columns are b e_i-e_(i+1); the last is q's base-b digits.
    Containment and determinant q are checked by KernelBasis. Neither the
    modulus nor entries pass through a machine-word integer conversion.
    """
    q, bits, base, k = radix_geometry(q, radix_bits)
    basis = matrix(ZZ, k, k)
    for j in range(k-1):
        basis[j, j], basis[j+1, j] = base, -1
    for i in range(k):
        basis[i, k-1] = (q >> (bits*i)) & (base-1)
    public = ModMatrixReference((tuple(base**i for i in range(k)),), q)
    return KernelBasis(public, basis)


class PrimeGadgetSampler:
    """Finite spherical Gaussian on G*x=u using independent complete blocks.

    Only the public k-by-k geometry is prepared, even for many rows. All
    syndrome and whole-call entropy limits are checked before reading a byte.
    SamplingAbort/entropy errors propagate without retries or substitutions.
    The TV bound assumes an ideal independent uniform byte stream; practical
    SecureRandom is the default and deterministic entropy is test-only.
    """

    security_claim = "none"
    backend_admitted = False
    parameters_are_formal = False

    def __init__(self, rows, q, width_squared, *, epsilon_bits=128, options=None, radix_bits=1):
        self.rows = exact_integer(rows, "gadget rows", minimum=1, maximum=MAX_ROWS)
        self.q, self.radix_bits, self.base, self.k = radix_geometry(q, radix_bits)
        self.dimension = self.rows*self.k
        if self.dimension > MAX_OUTPUT_COORDINATES:
            raise ValueError("public gadget output coordinate resource limit")
        self.options = MatrixFiniteOptions() if options is None else options
        if type(self.options) is not MatrixFiniteOptions:
            raise ValueError("explicit matrix finite options required")
        self.block = MatrixFiniteGPV(prime_gadget_kernel(self.q, radix_bits=self.radix_bits), width_squared,
            epsilon_bits=epsilon_bits, options=self.options,
            max_dimension=MAX_MODULUS_BITS, max_arithmetic_content_bytes=32*2**20)
        self.random_tape_bytes = self.rows*self.block.random_tape_bytes
        if self.random_tape_bytes > self.options.max_tape_bytes:
            raise ValueError("public gadget whole-call tape resource limit")
        self.tv_upper = min(QQ(1), self.rows*self.block.tv_upper)

    def _targets(self, syndrome):
        if isinstance(syndrome, (str, bytes, bytearray, memoryview)):
            raise ValueError("canonical gadget syndrome vector required")
        try:
            targets = tuple(islice(iter(syndrome), self.rows+1))
        except TypeError as exc:
            raise ValueError("canonical gadget syndrome vector required") from exc
        if len(targets) != self.rows:
            raise ValueError("public gadget syndrome dimension mismatch")
        return tuple(exact_integer(value, "gadget syndrome", minimum=0,
                                   maximum=self.q-1) for value in targets)

    def sample(self, syndrome, *, rng=None):
        targets = self._targets(syndrome)
        source = CheckedEntropy(SecureRandom() if rng is None else rng,
                                self.random_tape_bytes)
        result = tuple(x for target in targets
                       for x in self.block.sample((target,), rng=source))
        if any(sum((self.base**j)*result[i*self.k+j] for j in range(self.k)) % self.q != target
               for i, target in enumerate(targets)):
            raise ArithmeticError("public gadget product-coset equation failed")
        return result

    def public_certificate(self):
        """Only public gadget geometry; no secret trapdoor diagnostics."""
        result = dict(profile=VERSION if self.radix_bits == 1 else RADIX_VERSION, rows=self.rows, q=str(self.q),
            modulus_bits=self.q.bit_length(), gadget_block_dimension=self.k,
            output_coordinates=self.dimension, expanded_product_basis_entries=0,
            public_kernel_entries=self.k*self.k,
            coordinate_order=("row-major binary gadget blocks" if self.radix_bits == 1 else "row-major power-of-two radix gadget blocks"),
            complete_kernel_basis_verified=True, block=self.block.certificate(),
            tv_upper_including_abort=str(self.tv_upper),
            random_tape_bytes=self.random_tape_bytes,
            bound_model="independent uniform bytes; per-block TV union bound",
            complete_HIBE_domain_admitted=False, constant_time=False,
            security_claim="none", backend_admitted=False, parameters_are_formal=False)
        if self.radix_bits != 1:
            result.update(radix_bits=self.radix_bits, base=self.base, gadget_GS_squared_upper=self.base**2+1)
        return result
