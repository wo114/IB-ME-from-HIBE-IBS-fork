"""Executable Lai 2015 tag/type qualification; NOT a HIBE implementation."""
from dataclasses import dataclass
from fractions import Fraction


def _integer(value,name,low,high):
    if type(value) is not int or not low<=value<=high:raise ValueError(name)
    return value


@dataclass(frozen=True)
class Shape:
    prefix: int
    gadget: int

    def __post_init__(self):
        _integer(self.prefix,"prefix",1,4096);_integer(self.gadget,"gadget",1,64)

    @property
    def public_length(self):return self.prefix+self.gadget

    @property
    def trapdoor_shape(self):return self.prefix,self.gadget

    def delegate(self):return Shape(self.public_length,self.gadget)

    def check(self,rows,columns):
        if (type(rows) is not int or type(columns) is not int
                or (rows,columns)!=self.trapdoor_shape):raise ValueError("trapdoor/public dimension mismatch")


def split_ring_tag_witness(n=8,q=17):
    from sage.all import GF,PolynomialRing,ZZ
    _integer(n,"n",2,64);_integer(q,"q",3,2**31)
    if n&(n-1) or not ZZ(q).is_prime() or (q-1)%(2*n):raise ValueError("need power-of-two n, split prime q")
    poly=PolynomialRing(GF(q),"x");x=poly.gen();f=x**n+1
    roots=sorted(int(r) for r in f.roots(multiplicities=False))
    assert len(roots)==n
    root=roots[0];ring=poly.quotient(f,"z");tag=ring.gen()-root
    annihilator=ring(f.quo_rem(x-root)[0])
    assert tag!=0 and annihilator!=0 and tag*annihilator==0 and not tag.is_unit()
    try:tag**(-1)
    except (ArithmeticError,ZeroDivisionError) as exc:error=type(exc).__name__
    else:raise AssertionError("nonunit unexpectedly invertible")
    unit_count=(q-1)**n
    # Decrypt's literal h' != -hid condition only removes the zero sum.
    # Taking hid=1, h'=tag-1 passes that test while the sum is a zero divisor.
    hid=ring(1);hprime=tag-hid
    assert hprime!=-hid and not (hid+hprime).is_unit()
    return dict(n=n,q=q,root=root,tag=[int(v) for v in tag.list()],
        annihilator=[int(v) for v in annihilator.list()],inverse_error=error,
        roots=roots,unit_count=unit_count,total_count=q**n,
        nonunit_fraction=str(Fraction(q**n-unit_count,q**n)),
        nonzero_nonunit_fraction=str(Fraction(q**n-unit_count-1,q**n-1)),
        decrypt_literal_zero_check_passes=True,decrypt_sum_invertible=False)


def report():
    root=Shape(2,5);parent=root.delegate();leaf=parent.delegate()
    # Alg9 input a' has m+k entries, but its printed R has m+k rows;
    # the defining equation a^T R = h'g^T-a1^T instead requires m rows.
    return dict(schema="LAI-QUALIFICATION/1",stage="qualification_only",HIBE_implemented=False,
        algebra=split_ring_tag_witness(),
        dimensions=dict(gadget=5,root_public=root.public_length,root_trapdoor=root.trapdoor_shape,
            parent_public=parent.public_length,parent_trapdoor=parent.trapdoor_shape,
            leaf_public=leaf.public_length,leaf_trapdoor=leaf.trapdoor_shape,
            algorithm9_printed_rows=parent.public_length,algorithm9_required_rows=parent.prefix),
        unresolved=["unit-domain sampling and per-query/whole-lifetime abort accounting",
            "Alg9 trapdoor row count and Alg7 target-lattice type",
            "two-level public identity vector/encryption/noise definition omitted by 'Derive=Extract'",
            "finite perturbation/ring convolution distribution and anonymous HIBE theorem mapping"],
        adopted_scheme_modifications=[],security_claim="none",backend_admitted=False,
        parameters_are_formal=False,teaching_parameters=True)


if __name__=="__main__":
    import json
    print(json.dumps(report(),indent=2))
