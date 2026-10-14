"""Public-only verifier for the Foo-Li Figure 2 research implementation.

This contains no master trapdoor, master seed, or user signing seed. It uses the
same finite SHAKE candidate as foo_li_runtime_reference; it is not an ideal-RO
or security-admission claim.
"""

from sage.all import ZZ, matrix

from ibme.core.types import validate_bytes, validate_identity
from .online_mp12_reference import modular_matrix
from .online_gaussian_reference import exact_integer
from .foo_li_runtime_reference import (
    DOMAINS, ResearchConfig, ShakeOracleCandidate, modular_hash, public_context,
    verify_equation,
)


class PublicVerifier:
    __slots__ = ("config", "epoch", "public", "context", "oracle")

    def __init__(self, config, epoch, public, *, oracle=None):
        if not isinstance(config, ResearchConfig):
            raise ValueError("Need ResearchConfig")
        self.config = config
        self.epoch = validate_identity(epoch, max_bytes=256)
        self.public = modular_matrix(public, config.q, (config.n, config.m), "Foo-Li public key")
        self.context = public_context(config, self.epoch, self.public)
        self.oracle = ShakeOracleCandidate() if oracle is None else oracle

    def _identity(self, identity):
        return validate_identity(identity, max_bytes=self.config.identity_max_bytes)

    def _message(self, message):
        message = validate_bytes(message)
        if len(message) > self.config.message_max_bytes:
            raise ValueError("Message exceeds research limit")
        return message

    def identity_matrix(self, identity, bit):
        identity = self._identity(identity)
        bit = exact_integer(bit, "bit", maximum=1)
        c = self.config
        values = modular_hash(self.oracle, self.context, c, DOMAINS[2],
            (identity, bytes([bit])), c.n*c.w)
        return matrix(ZZ, c.n, c.w, values)

    def syndrome(self, identity, message):
        return modular_hash(self.oracle, self.context, self.config, DOMAINS[3],
            (self._identity(identity), self._message(message)), self.config.n)

    def verify(self, identity, message, signature):
        identity, message = self._identity(identity), self._message(message)
        return verify_equation(self.config, self.public, identity, message,
            signature, self.identity_matrix, self.syndrome)
