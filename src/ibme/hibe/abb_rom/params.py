"""Independent ABB-ROM finite configuration; no old Params conversion.

Parsing is portable and entropy-free. Algebraic primality, same-group width
and noise checks are performed by the Sage setup gate, not claimed by JSON.
Security flags are fixed none/false. Complete canonical fields bind objects.
"""

from dataclasses import asdict, dataclass, fields
import json
import re

from ibme.core.errors import InvalidParameterError, SerializationError

SCHEMA = "IBME/ABB-ROM/AP09-MATRIX-FINITE/1"
MAX_CONFIG_BYTES = 16384
Q160 = 730750818665451459101842416358141509827966271787


def unique_fields(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate configuration field")
        result[name] = value
    return result


@dataclass(frozen=True)
class ABBROMParams:
    name: str = "abb-rom-ap09-n1-q160-research"
    n: int = 1
    q: int = Q160
    random_rows: int = 320
    root_m1: int = 320
    root_m2: int = 960
    hadamard_scale: int = 56
    matrix_gaussian_squared_width: int = 623798000
    sigma1_squared: int = 19480480075862507520000000
    sigma2_squared: int = 436067107841351475394815841680752640000000000000
    tau2_squared: int = 312572902900680737563003995316763492352000000000000000
    noise_width_numerator: int = 4
    noise_width_denominator: int = 1
    epsilon_bits: int = 128
    error_bits: int = 128
    encapsulation_budget: int = 2**20
    identity_max_bytes: int = 86
    payload_max_bytes: int = 32
    max_parents: int = 2
    max_children_per_parent: int = 2
    sample_r_max_matrices: int = 5
    uniform_trials: int = 192
    finite_tail_bits: int = 128
    finite_mass_bits: int = 256
    finite_precision_bits: int = 320
    finite_abort_bits: int = 128
    max_tape_bytes: int = 2**44
    max_blob_bytes: int = 128 * 2**20
    normalization: str = "matrix-fixed-lll-075-0501-exact074-v1"
    matrix_oracle: str = "shake256-block-tape-engineering-v1"
    security_claim: str = "none"
    backend_admitted: bool = False
    parameters_are_formal: bool = False

    def __post_init__(self):
        if not isinstance(self.name, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", self.name):
            raise InvalidParameterError("canonical ABB profile name required")
        bounds = {
            "n": (1, 64), "q": (3, 2**256-1), "random_rows": (1, 1536),
            "root_m1": (1, 1536), "root_m2": (1, 1536), "hadamard_scale": (1, 4096),
            "matrix_gaussian_squared_width": (1, 2**192), "sigma1_squared": (1, 2**192),
            "sigma2_squared": (1, 2**192), "tau2_squared": (1, 2**192),
            "noise_width_numerator": (1, 2**64), "noise_width_denominator": (1, 2**64),
            "epsilon_bits": (2, 4096), "error_bits": (8, 4096), "encapsulation_budget": (1, 2**32),
            "identity_max_bytes": (1, 256), "payload_max_bytes": (0, 32),
            "max_parents": (1, 8), "max_children_per_parent": (1, 8),
            "sample_r_max_matrices": (1, 1024), "uniform_trials": (1, 4096),
            "finite_tail_bits": (8, 1024), "finite_mass_bits": (32, 2048),
            "finite_precision_bits": (96, 4096), "finite_abort_bits": (8, 1024),
            "max_tape_bytes": (1, 2**44), "max_blob_bytes": (1024, 128*2**20),
        }
        for name, (low, high) in bounds.items():
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise InvalidParameterError(f"{name}: exact bounded integer required")
        if self.q % 2 == 0 or self.dimension > 1536:
            raise InvalidParameterError("odd q and complete dimension <=1536 required")
        if self.root_m1 < self.random_rows or self.random_rows <= self.n * (self.q-1).bit_length():
            raise InvalidParameterError("AP09 m1/d dimension relation failed")
        if self.root_m2 < 2*self.n*(self.q-1).bit_length()+2*self.random_rows:
            raise InvalidParameterError("AP09 digit/Hadamard block dimensions failed")
        remaining = self.root_m2-2*self.n*(self.q-1).bit_length()
        hadamard_width = 1 << (remaining.bit_length()-1)
        if 4*self.random_rows*self.root_m2 > self.hadamard_scale**2*hadamard_width:
            raise InvalidParameterError("AP09 deterministic quality condition failed")
        if self.dimension <= 6*self.n*(self.q-1).bit_length():
            raise InvalidParameterError("conservative strict ABB Setup dimension condition failed")
        if (self.normalization not in ("matrix-fixed-lll-075-0501-exact074-v1",
                "matrix-flatter-lll-075-0501-exact074-v2",
                "matrix-flatter-rootgs16-lll-075-exact074-v3",
                "matrix-flatter-rootgs256-nativegram-exact074-v4",
                "matrix-flatter-allgs256-nativegram-exact074-v5") or
                self.matrix_oracle != "shake256-block-tape-engineering-v1"):
            raise InvalidParameterError("unknown ABB finite implementation version")
        if (self.security_claim != "none" or self.backend_admitted is not False or
                self.parameters_are_formal is not False):
            raise InvalidParameterError("ABB finite research security flags must remain none/false")

    @property
    def dimension(self):
        return self.root_m1+self.root_m2

    @property
    def normalized_root_gs_squared_bound(self):
        if self.normalization == "matrix-flatter-rootgs16-lll-075-exact074-v3":return 16
        if self.normalization in ("matrix-flatter-rootgs256-nativegram-exact074-v4",
                "matrix-flatter-allgs256-nativegram-exact074-v5"):return 256
        return None

    @property
    def normalized_level_gs_squared_bound(self):
        return 256 if self.normalization == "matrix-flatter-allgs256-nativegram-exact074-v5" else None

    @property
    def identity_bytes(self):
        """Public assembly/Hybrid capability alias; no Params conversion."""
        return self.identity_max_bytes

    @property
    def max_message_bytes(self):
        return self.payload_max_bytes

    def to_record(self):
        return asdict(self)

    def to_bytes(self):
        return json.dumps({"schema": SCHEMA, "params": self.to_record()},
            sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

    @classmethod
    def from_bytes(cls, raw):
        if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_CONFIG_BYTES:
            raise SerializationError("bounded ABB configuration bytes required")
        try:
            record = json.loads(raw.decode("ascii"), object_pairs_hook=unique_fields,
                parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
            if type(record) is not dict or set(record) != {"schema", "params"} or record["schema"] != SCHEMA:
                raise ValueError("ABB configuration version/shape")
            values = record["params"]
            if type(values) is not dict or set(values) != {f.name for f in fields(cls)}:
                raise ValueError("ABB configuration requires all exact fields")
            result = cls(**values)
            if result.to_bytes() != raw:
                raise ValueError("noncanonical ABB configuration")
            return result
        except (ValueError, TypeError, UnicodeError, InvalidParameterError) as exc:
            raise SerializationError("invalid canonical ABB configuration") from exc
