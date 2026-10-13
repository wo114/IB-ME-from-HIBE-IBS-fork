"""Real Algorithms 2/3/7, with explicit zeta-consistent signature shape."""
from fractions import Fraction

from .algebra import constant, identity, matvec, response_from_values, signing_matrix, multiply, zeta_star
from .geometry import Widths, master_geometry, signature_geometry
from .sampling import GadgetSampler, TableOptions, extract_with_gadget


def options(config):
    from .full_sampling import FullSamplingOptions
    return FullSamplingOptions(precision_bits=config.precision_bits,ticket_bits=config.ticket_bits,
                               tail_bits=config.scalar_tail_bits,mass_bits=config.scalar_mass_bits)


def sample_geometry(geometry,degree,r_squared,rng,opt):
    """Alg3: exact discrete lower block, conditional block SampleF upper."""
    from .full_sampling import sample_scalar_vector, sample_p
    lower_count=len(geometry.center_operator[0])
    lower=sample_scalar_vector(geometry.lower_scalar,(Fraction(0),)*lower_count,rng=rng,options=opt)
    center=geometry.conditioned_center(lower)
    upper=sample_p(geometry.conditional_shape,center,degree,r_squared,rng=rng,options=opt)
    coefficients=tuple(upper)+tuple(lower)
    return tuple(tuple(coefficients[i:i+degree]) for i in range(0,len(coefficients),degree))


def extract_tail(master,target,rng):
    pk,c=master.public_key,master.public_key.config
    p=c.algebra
    geom=master_geometry(p,master.r,Widths(c.master_first_squared,c.master_second_squared,c.r_squared))
    perturbation=sample_geometry(geom,p.degree,c.r_squared,rng,options(c))
    gadget=GadgetSampler(p,c.gadget_width_squared,TableOptions(tail_bits=c.gadget_tail_bits,mass_bits=c.scalar_mass_bits,
                                                           precision_bits=c.precision_bits,max_radius=128))
    raw=extract_with_gadget(pk.public,master.r,target,perturbation,gadget,rng=rng)
    return raw.tail


def sign_attempt(key,message,rng):
    from .full_sampling import sample_scalar_vector
    from .hashing import identity_target,message_challenge
    pk,c=key.public_key,key.public_key.config
    p=c.algebra; y=key.full_vector; target=identity_target(pk,key.identity)
    geom=signature_geometry(p,y,Widths(c.signature_first_squared,c.signature_second_squared,c.r_squared),
                            noise_factor=c.signature_noise_factor)
    opt=options(c)
    perturbation=sample_geometry(geom,p.degree,c.r_squared,rng,opt)
    commitment=matvec(p,signing_matrix(pk.public,target),perturbation,2*p.modulus)
    challenge=message_challenge(pk,commitment,message)
    # 1/zeta=zeta*/2 in Q[X]/(X^n+1), with exact half-integer centers.
    center=tuple(Fraction(-x,2) for x in multiply(zeta_star(p),challenge))
    u=tuple(sample_scalar_vector(c.r_squared,center,rng=rng,options=opt))
    response=response_from_values(pk.public,target,y,perturbation,u,challenge)
    return response,challenge
