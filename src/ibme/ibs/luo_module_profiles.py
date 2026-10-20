"""Explicit, versioned Luo research profiles.

C64B fixes all 17 wire fields rather than inheriting future constructor defaults.
The old LuoModuleParams() default and the two signature codecs are unchanged.
Current project admission is attached by the public registry to this exact
snapshot; the primitive parameter wire remains backward compatible.
"""

from .luo_module import LuoModuleParams

C64B_PROFILE_ID = "luo-module-c64b-v1"


def c64b_params() -> LuoModuleParams:
    """Return the frozen step-22 candidate used by the admitted ``c64b`` preset."""
    return LuoModuleParams(
        degree=256, k=11, l=10, q=274877844481, root=153250464611,
        eta=1, kappa=64, gamma1=190000, gamma2=60000000000,
        gamma3=27487784448, dropped_bits=28, identity_max_bytes=64,
        message_max_bytes=4096, max_extract_attempts=4096,
        max_sign_attempts=4096, max_uniform_attempts=128,
        max_cached_identities=64,
    )


def is_c64b_profile(params: object) -> bool:
    """Exact public parameter match, including resource caps; not a safety test."""
    return type(params) is LuoModuleParams and params == c64b_params()
