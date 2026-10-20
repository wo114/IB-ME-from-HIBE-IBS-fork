"""Complete immutable parameter snapshot, without implicit wire defaults."""
from dataclasses import asdict, dataclass
import json

from ibme.core.errors import InvalidParameterError, SerializationError
from ibme.core.security import (ADMITTED_SECURITY, PROJECT_SECURITY_CLAIM,
                                UNADMITTED_SECURITY, security_tuple)
from .ordinary import PROFILES

VERSION = "IBME/CERTIBS/1"


@dataclass(frozen=True)
class CertifiedIBSParams:
    base_algorithm: str = "ml-dsa-44"
    identity_bytes: int = 64
    message_max_bytes: int = 65536
    max_identities: int = 16
    timeout_seconds: int = 30
    security_claim: str = PROJECT_SECURITY_CLAIM
    backend_admitted: bool = True
    parameters_are_formal: bool = True

    def __post_init__(self):
        if type(self.base_algorithm) is not str or self.base_algorithm not in PROFILES:
            raise InvalidParameterError("unsupported certified IBS ordinary signature algorithm")
        for name, low, high in (("identity_bytes", 1, 4096), ("message_max_bytes", 0, 1024 * 1024),
                                ("max_identities", 1, 256), ("timeout_seconds", 1, 300)):
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise InvalidParameterError(f"certified IBS {name} outside resource bounds")
        if (type(self.security_claim) is not str or type(self.backend_admitted) is not bool
                or type(self.parameters_are_formal) is not bool
                or security_tuple(self) not in (ADMITTED_SECURITY,UNADMITTED_SECURITY)):
            raise InvalidParameterError("certified IBS requires current admission or an exact legacy snapshot")

    def to_bytes(self):
        return json.dumps(dict(version=VERSION, **asdict(self)), sort_keys=True,
                          separators=(",", ":"), ensure_ascii=True).encode("ascii")

    @classmethod
    def from_bytes(cls, data):
        if type(data) is not bytes or len(data) > 4096:
            raise SerializationError("certified IBS parameter size/type")
        try:
            values = json.loads(data)
            if type(values) is not dict or set(values) != {"version", *cls.__dataclass_fields__}:
                raise ValueError("incomplete/unknown certified IBS parameter fields")
            if values.pop("version") != VERSION:
                raise ValueError("certified IBS parameter version")
            result = cls(**values)
            if result.to_bytes() != data:
                raise ValueError("noncanonical certified IBS parameters")
            return result
        except (TypeError, ValueError, UnicodeError, RecursionError, InvalidParameterError) as exc:
            raise SerializationError("invalid certified IBS parameters") from exc
