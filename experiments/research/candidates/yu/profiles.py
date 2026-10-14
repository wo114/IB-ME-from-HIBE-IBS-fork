"""Executable correctness profile only, deliberately not a security parameter set."""

from . import bpr
from .standalone import Params
from experiments.research.chkp_genbasis import AP09Parameters


def tiny_profile():
    """15 -> 17 -> 19 dimensional real lattice path, BPR matrix dimension 2.

    q=3 and the large norm threshold permit the public forgery q*e_1.
    This profile must NEVER be cited as anonymous, unforgeable or PQ secure.
    """
    return Params(
        root=AP09Parameters(n=1, q=3, random_rows=3, m1=3, m2=12, hadamard_scale=8),
        identity_prf=bpr.make_spec(bpr.Params(input_bits=2)),
        signing_prf=bpr.make_spec(bpr.Params(input_bits=8)),
        message_bits=2, salt_bits=4,
        gamma_squared=32768, delta_squared=67108864,
        max_vectors=32, epsilon_bits=16, postprocess=True,
    )
