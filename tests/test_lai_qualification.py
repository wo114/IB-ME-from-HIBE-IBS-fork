"""Source-condition witnesses, not a successful HIBE lifecycle."""
import pytest
from experiments.research.candidates.lai.qualification import Shape,split_ring_tag_witness,report


@pytest.mark.parametrize("prefix,k",[(1,1),(2,5),(16,17),(32,32)])
def test_two_real_extensions_require_growing_trapdoors(prefix,k):
    root=Shape(prefix,k);parent=root.delegate();leaf=parent.delegate()
    assert root.public_length==prefix+k
    assert parent.trapdoor_shape==(prefix+k,k) and leaf.trapdoor_shape==(prefix+2*k,k)
    parent.check(prefix+k,k)
    with pytest.raises(ValueError):parent.check(prefix+2*k,k)  # Alg9 printed shape
    with pytest.raises(ValueError):leaf.check(prefix+k,k)     # Extract copy at the next level


@pytest.mark.parametrize("values",[(True,5),(2,False),(0,5),(2,0),(4097,2),(2,65)])
def test_dimension_limits(values):
    with pytest.raises(ValueError):Shape(*values)


@pytest.mark.parametrize("n,q",[(2,5),(4,17),(8,17),(16,97)])
def test_nonzero_tag_and_decrypt_zero_check_are_insufficient(n,q):
    pytest.importorskip("sage.all",reason="prescribed WSL Sage")
    witness=split_ring_tag_witness(n,q)
    assert witness["unit_count"]==(q-1)**n
    assert witness["decrypt_literal_zero_check_passes"] and not witness["decrypt_sum_invertible"]
    assert witness["inverse_error"] in ("ArithmeticError","ZeroDivisionError")


def test_qualification_does_not_register_or_claim_a_hibe():
    pytest.importorskip("sage.all",reason="prescribed WSL Sage")
    result=report()
    assert result["stage"]=="qualification_only" and not result["HIBE_implemented"]
    assert result["adopted_scheme_modifications"]==[]
    from ibme.assembly.registry import default_registry
    assert default_registry().get("hibe","lai-ideal-hibe").available
