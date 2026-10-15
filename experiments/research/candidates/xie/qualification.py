"""Literal-paper counterexamples. Repairs are named, not paper reproduction."""
from fractions import Fraction
from .ring import add,mul,neg,rotations


def equation_witness(n=16,q=97):
    if n not in (16,32) or q!=97:raise ValueError("fixed public qualification domain")
    one=(1,)+(0,)*(n-1);two=(2,)+(0,)*(n-1);zero=(0,)*n
    f,g,F,G=one,two,zero,(q,)+(0,)*(n-1);h=two
    assert add(mul(f,G),neg(mul(g,F)))==G
    literal=add(f,mul(h,g,q),q);corrected=add(neg(g),mul(h,f,q),q)
    assert literal!=(0,)*n and corrected==(0,)*n
    return dict(n=n,q=q,h=list(h),fG_minus_gF=list(G),
        literal_first_row_syndrome=list(literal),rotated_first_row_syndrome=list(corrected),
        literal_basis_in_claimed_kernel=False,rotated_basis_in_claimed_kernel=True,
        row_coordinate_repair="(f,g),(F,G) -> (-g,f),(-G,F)")


def gaussian_witness():
    # For b=2 and width s=4, coordinates require width 2, not width 1.
    # A sampler of z centered at 1/2 gives P(z=0)=P(z=1). Returning -2z
    # therefore gives P(v=0)=P(v=-2), unlike D_(2Z),4,1.
    return dict(basis_length=2,width=4,center=1,
        printed_coordinate_width=str(Fraction(4,2**2)),gpv_coordinate_width=str(Fraction(4,2)),
        printed_output_sign=-1,gpv_output_sign=1,
        printed_log_probability_ratio_minus2_over0=0,
        target_log_probability_ratio_minus2_over0="-pi/2")


def report():
    return dict(schema="XIE-LITERAL-QUALIFICATION/1",stage="qualification_and_corrected_equation_study",
        literal_source_reproduction=False,common_IBSBackend=False,equation=equation_witness(),
        gaussian=gaussian_witness(),printed_table_q=[227,225,233,218,226],
        table_not_reinterpreted_as_exponents=True,prime_requirement_conflicts=[225,218,226],
        adopted_research_repairs=["Alg4 sample units, as Alg3 does; h=g/f needs inverse",
            "rotate NTRU basis to the exact s1+h*s2=t kernel",
            "use GPV08 SampleD width s/||b*|| and positive lattice accumulator",
            "separate explicitly named root/extract/sign widths and finite resource limits",
            "LLL unimodular preconditioning of the same complete integer kernel",
            "bounded SHAKE instantiations, Gaussian and Bernoulli rounding/truncation/abort"],
        not_admitted=["author clarification / full paper parameter correspondence",
            "near-uniform NTRU public distribution and fixed identity ROM proof",
            "query-budget total conditional TV and signature rejection loss",
            "strong unforgeability / QROM / real HIBE composition"],
        security_claim="none",backend_admitted=False,parameters_are_formal=False)


if __name__=="__main__":
    import json
    print(json.dumps(report(),indent=2))
