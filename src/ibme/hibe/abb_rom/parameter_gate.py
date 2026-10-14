"""Paper setup/primitive-domain boundary; never a security admission.

ABB10 section4.2 requires m > 6*n*log(q). The checked base2 ceiling below
is a conservative explicit sufficient test, without pretending an unspecified
omega factor or TrapGen's hidden constants have been instantiated.
"""

from ibme.core.errors import InvalidParameterError


def setup_dimension_report(n,m,q):
    if (type(n) is not int or not 1<=n<=16384 or type(m) is not int or not 1<=m<=2**20
            or type(q) is not int or not 3<=q<2**256):
        raise InvalidParameterError("exact bounded ABB dimension/modulus values required")
    log_q_ceiling=(q-1).bit_length()
    minimum=6*n*log_q_ceiling+1
    return dict(n=n,m=m,q=q,ceil_log2_q=log_q_ceiling,
        conservative_strict_dimension_minimum=minimum,
        paper_dimension_sufficient_checked=m>=minimum,
        comparison_method="m >= 6*n*ceil(log2(q))+1; sufficient, not necessary",
        fixed_primitive_domain=m<=192 and q<=2**61-1,prime_modulus_verified=False,
        full_HIBE_backend_implemented=False,
        actual_ABB_TrapGen_verified=False,paper_omega_factors_verified=False,
        root_and_delegation_distributions_verified=False,LWE_hardness_checked=False,
        parameters_are_formal=False,security_claim="none",backend_admitted=False)
