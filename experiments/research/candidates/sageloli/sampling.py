"""Full-dimensional MP12 perturbations for Sageloli's two research routes.

Density widths use exp(-pi*x^2/s^2), not physical standard deviations.
The existing finite SampleF / block-Schur numerical implementation is reused;
its continuous-stage and total TV errors remain uncertified. No secret plans
or samples are serialized. See the source map for the root sign convention.
"""
from . import algebra


def prepare(a, trapdoor, k, width_squared, *, degree=1):
    """Check A[-T;I]=G and the *raw integer* PSD condition before drawing."""
    from .probe import prepare_sampler

    return prepare_sampler(a, trapdoor, k, width_squared,
        mode="global" if degree == 1 else "block-schur", block_size=degree)


def draw(a, prepared, target, k, rng):
    from sage.all import ZZ, matrix
    from .probe import sample_preimage

    return tuple(int(x) for x in sample_preimage(matrix(ZZ, a), prepared, target, k, rng))


def root_plan(public, root, params):
    # Stored R satisfies A[R;I]=G. The sampler interface stores T=-R.
    negative = tuple(tuple(-x for x in row) for row in root)
    return prepare(public, negative, params.k, params.s_id_squared,
                   degree=getattr(params, "d", 1))


def signing_plan(public, h, trapdoor, params):
    return prepare(algebra.hstack(public, h), trapdoor, params.k,
                   params.s_sign_squared, degree=getattr(params, "d", 1))


def cached_plan(owner, name, binding, make):
    """Only per-object private caches; recovered objects prepare fresh plans."""
    old = getattr(owner, name, None)
    if old is not None and old[0] == binding:
        return old[1]
    plan = make()
    object.__setattr__(owner, name, (binding, plan))
    return plan


def delegate_matrix(a, prepared, target, params, rng):
    columns = [draw(a, prepared, tuple(row[j] for row in target), params.k, rng)
               for j in range(params.nk)]
    return tuple(tuple(col[i] for col in columns) for i in range(params.m))


def delegate_ring(a, prepared, target, params, rng):
    # Exactly k ring calls. Other coefficient columns are their rotations.
    columns = [draw(a, prepared, target[j], params.k, rng) for j in range(params.k)]
    return tuple(tuple(tuple(columns[j][i*params.d+h] for h in range(params.d))
                       for j in range(params.k)) for i in range(params.l))


def public_certificate(prepared):
    return prepared[1].public_certificate()
