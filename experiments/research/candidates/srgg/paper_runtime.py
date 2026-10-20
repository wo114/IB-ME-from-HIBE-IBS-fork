"""Runtime arithmetic reserve around the frozen Table-4 research backend.

Historical certificates continue to bind paper_backend.py and paper_samplef.py
byte for byte. The public assembly uses this adapter to accommodate the
8192-term series in exact rational storage. Historical certificate bounds are
still scoped to their recorded source, options, witnesses and input domains.
"""
from collections import OrderedDict
from dataclasses import asdict, dataclass, fields
from threading import Lock

from .paper_backend import Backend as ResearchBackend
from .paper_objects import SigningKey
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

    def __init__(self, *, rng=None, setup_max_attempts=64, sign_max_attempts=64,
                 plan_cache_entries=2):
        super().__init__(rng=rng, setup_max_attempts=setup_max_attempts,
                         sign_max_attempts=sign_max_attempts)
        self.scalar_options = PaperScalarOptions(**{**asdict(self.scalar_options),
                                                    "rational_bits": 32768})
        self._plan_lock = Lock()
        self.configure_sign_plan_cache(plan_cache_entries)

    def configure_sign_plan_cache(self, capacity):
        """Bound secret-dependent preparation retention; zero disables reuse.

        Entries keep a strong reference to the immutable original key, preventing
        id reuse. No random sample or random-source state is retained here.
        """
        if type(capacity) is not int or not 0 <= capacity <= 16:
            raise ValueError("sign plan cache capacity must be an integer in [0, 16]")
        with self._plan_lock:
            self._plan_capacity = capacity
            self._sign_plans = OrderedDict()
            self._plan_hits = self._plan_misses = 0

    def clear_sign_plan_cache(self):
        with self._plan_lock:
            self._sign_plans.clear()

    def sign_plan_cache_info(self):
        with self._plan_lock:
            return dict(capacity=self._plan_capacity, entries=len(self._sign_plans),
                        hits=self._plan_hits, misses=self._plan_misses)

    def prepare_signing(self, key):
        """Explicitly pay deterministic preparation before repeated signing."""
        return self._sign_plan(key).public_certificate()

    def _sign_plan(self, key):
        if type(key) is not SigningKey:
            raise TypeError("paper SigningKey required")
        options = (self.series_options, self.scalar_options)
        with self._plan_lock:
            entry = self._sign_plans.get(id(key))
            if entry is not None and entry[0] is key and entry[1] == options:
                self._plan_hits += 1
                self._sign_plans.move_to_end(id(key))
                return entry[2]
            self._plan_misses += 1
            plan = self._build_sign_plan(key)
            if self._plan_capacity:
                self._sign_plans[id(key)] = (key, options, plan)
                self._sign_plans.move_to_end(id(key))
                while len(self._sign_plans) > self._plan_capacity:
                    self._sign_plans.popitem(last=False)
            return plan

    def _build_sign_plan(self, key):
        return super()._sign_plan(key)
