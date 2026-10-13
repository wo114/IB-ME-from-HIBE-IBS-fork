"""Real MP12 Algorithms 1/3/4; lazy Sage dependency, no teaching fallback.

Only vectors and trapdoors leave this module. Actual perturbation covariance
certificates and SampleD auxiliary traces are secret and never published.
"""
from functools import lru_cache

from sage.all import ZZ, matrix

from experiments.research.online_gaussian_reference import OnlineOptions
from experiments.research.online_mp12_reference import OnlineGaussianGenTrap, sampler_for_quality
from experiments.research.gaussian_reference import SamplingAbort


def _rows(value): return tuple(tuple(int(x) for x in row) for row in value.rows())


@lru_cache(maxsize=8)
def prepare(params):
    """Admit complete PUBLIC width classes before reading secret entropy."""
    p, options = params, OnlineOptions(**params.online_options())
    generator = OnlineGaussianGenTrap(p.q, p.n, p.m_bar, p.generation_width_squared, options=options)
    # Zero probes verify class resources, not the quality of an actual secret.
    for columns, quality in ((p.m_bar, p.master_quality), (p.m, p.user_quality)):
        _, sampler = sampler_for_quality(p.q, matrix(ZZ, p.n, columns), matrix(ZZ, columns, p.w),
                                        quality, r_squared=p.r_squared, gamma=p.gamma, options=options)
        if sampler is None: raise ValueError("public sampler class could not be prepared")
    return generator


def generate(params, rng):
    generated = prepare(params).generate(rng=rng)
    if generated.norm_squared > params.master_quality:
        raise SamplingAbort("root quality exceeded; no retry or changed public width")
    return _rows(generated.public), _rows(generated.trapdoor)


def _sampler(pk, base, trapdoor, quality):
    p = pk.params
    status, sampler = sampler_for_quality(p.q, base, trapdoor, quality,
        r_squared=p.r_squared, gamma=p.gamma, options=OnlineOptions(**p.online_options()))
    if sampler is None: raise SamplingAbort("secret trapdoor exceeded fixed public quality class")
    return sampler


def delegate(master, extension, rng):
    pk, p = master.public_key, master.public_key.params
    base = tuple(row[:p.m_bar] for row in pk.a)
    sampler = _sampler(pk, base, master.trapdoor, p.master_quality)
    # Each column has independent fresh sampler randomness. Wang has no
    # per-identity deterministic random-tape requirement (unlike Foo–Li).
    columns = []
    for j in range(p.w):
        target = tuple((int(sampler.g[i, j])-extension[i][j]) % p.q for i in range(p.n))
        columns.append(sampler.sample(target, rng=rng))
    trapdoor = tuple(tuple(columns[j][i] for j in range(p.w)) for i in range(p.m))
    if sum(x*x for row in trapdoor for x in row) > p.user_quality:
        raise SamplingAbort("delegated quality exceeded; no retry or reselection")
    return trapdoor


def sample_signature(key, syndrome, rng):
    sampler = _sampler(key.public_key, key.public_key.a, key.trapdoor, key.public_key.params.user_quality)
    return tuple(sampler.sample(syndrome, rng=rng))
