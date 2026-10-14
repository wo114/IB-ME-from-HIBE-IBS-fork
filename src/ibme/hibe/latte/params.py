"""One pinned LATTE-3 author profile, with explicit research-only framing."""
from dataclasses import dataclass
from ibme.core.errors import InvalidParameterError

REVISION = "18cfbf9a671fca34785583b58ab9f28e3be21a3c"
VERSION = "IBME/LATTE3/COSAC-FIX/1"
N, Q = 1024, 68718428161
SIGMA = ("6777.5879662983919609175926", "351968.36683734171059914430",
         "22559988.027951553365675150")  # standard deviations, not exp(-pi*x²/s²) widths


@dataclass(frozen=True)
class LATTEParams:
    message_mode: str = "seed32"
    identity_bytes: int = 86
    max_receivers: int = 2
    max_children: int = 2
    native_timeout_seconds: int = 60

    def __post_init__(self):
        if type(self.message_mode) is not str or self.message_mode not in ("seed32", "framed32"):
            raise InvalidParameterError("LATTE needs explicit seed32 or framed32 mode")
        for name, low, high in (("identity_bytes", 1, 86), ("max_receivers", 1, 8),
                ("max_children", 1, 8), ("native_timeout_seconds", 1, 300)):
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise InvalidParameterError("LATTE exact bounded parameter required: " + name)

    @property
    def max_payload_bytes(self):
        return 32 if self.message_mode == "seed32" else 28

    @property
    def max_message_bytes(self):
        """Public capacity field consumed by the existing Hybrid adapter."""
        return self.max_payload_bytes

    def record(self):
        return dict(version=VERSION, source_revision=REVISION, n=N, q=Q, depth=2,
            sigma_standard_deviations=list(SIGMA), fft_precision_bits=768,
            reduce_k_precision_bits=[256, 768], message_mode=self.message_mode,
            identity_bytes=self.identity_bytes, max_receivers=self.max_receivers,
            max_children=self.max_children, native_timeout_seconds=self.native_timeout_seconds,
            security_claim="none", backend_admitted=False, parameters_are_formal=False)

    @classmethod
    def from_record(cls, value):
        from .codec import canonical
        if type(value) is not dict:
            raise ValueError("LATTE parameter record required")
        names = ("message_mode", "identity_bytes", "max_receivers", "max_children", "native_timeout_seconds")
        p = cls(**{key: value[key] for key in names})
        if canonical(p.record()) != canonical(value):
            raise ValueError("LATTE incomplete/unknown/changed parameter snapshot")
        return p
