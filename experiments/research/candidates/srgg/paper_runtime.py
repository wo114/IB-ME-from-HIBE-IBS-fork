"""Runtime arithmetic reserve around the frozen Table-4 research backend.

Historical certificates continue to bind paper_backend.py and paper_samplef.py
byte for byte. The public assembly uses this adapter to accommodate the
8192-term series in exact rational storage. Historical certificate bounds are
still scoped to their recorded source, options, witnesses and input domains.
"""
from dataclasses import asdict, dataclass, fields

from .paper_backend import Backend as ResearchBackend
from .structured_samplef import _bounded
from .wide_scalar import WideScalarOptions


@dataclass(frozen=True)
class PaperScalarOptions(WideScalarOptions):
    """Retain the finite Gaussian law and enlarge exact-input storage only."""

    rational_bits: int = 32768

    def __post_init__(self):
        _bounded(self.rational_bits, "paper scalar rational_bits", 128, 32768)
        ordinary = {item.name: getattr(self, item.name) for item in fields(WideScalarOptions)}
        ordinary["rational_bits"] = min(self.rational_bits, 8192)
        checked = WideScalarOptions(**ordinary)
        for item in fields(WideScalarOptions):
            if item.name != "rational_bits":
                object.__setattr__(self, item.name, getattr(checked, item.name))


class Backend(ResearchBackend):
    """Use the same algorithms and widths with explicit runtime storage."""

    def __init__(self, *, rng=None, setup_max_attempts=64, sign_max_attempts=64):
        super().__init__(rng=rng, setup_max_attempts=setup_max_attempts,
                         sign_max_attempts=sign_max_attempts)
        self.scalar_options = PaperScalarOptions(**{**asdict(self.scalar_options),
                                                    "rational_bits": 32768})
