"""Strict five-role object codecs and private path/failed-address binding."""

from dataclasses import replace
import pytest

from ibme.core.encoding import encode_bytes
from ibme.core.errors import SerializationError
from ibme.hibe.abb_rom.params import ABBROMParams
from ibme.hibe.abb_rom.objects import ABBPublicKey, ABBMasterSecret, ABBLevel1Key, ABBLevel2Key, ABBCiphertext, MAGIC


def params():
    return replace(ABBROMParams(),name="abb-objects-public-fixture",q=101,random_rows=8,
        root_m1=8,root_m2=36,hadamard_scale=40,matrix_gaussian_squared_width=16)


def public():
    p=params()
    return ABBPublicKey(p,(tuple((j*j+3)%101 for j in range(p.dimension)),),(7,))


def test_public_and_ciphertext_roundtrip_canonical_and_no_identity_header():
    pk=public()
    assert ABBPublicKey.from_bytes(pk.to_bytes())==pk
    ct=ABBCiphertext(pk.params,pk.context,1,tuple(tuple((j+i)%101 for j in range(pk.params.dimension+1)) for i in range(8)))
    assert ABBCiphertext.from_bytes(ct.to_bytes())==ct
    assert b"Bob" not in ct.to_bytes() and b"Alice" not in ct.to_bytes()
    empty=ABBCiphertext(pk.params,pk.context,0,())
    assert ABBCiphertext.from_bytes(empty.to_bytes())==empty


@pytest.mark.parametrize("role",[ABBPublicKey,ABBCiphertext])
def test_public_wire_rejects_truncate_append_duplicate_version(role):
    pk=public()
    value=pk if role is ABBPublicKey else ABBCiphertext(pk.params,pk.context,0,())
    raw=value.to_bytes()
    for invalid in [raw[:-1],raw+b"x",raw+raw,bytes([raw[0]^1])+raw[1:]]:
        with pytest.raises(SerializationError):role.from_bytes(invalid)


def test_residue_dimensions_and_noncanonical_coefficients_rejected():
    pk=public()
    with pytest.raises(SerializationError):ABBPublicKey(pk.params,((101,)*44,),(7,))
    with pytest.raises(SerializationError):ABBPublicKey(pk.params,((True,)*44,),(7,))
    with pytest.raises(SerializationError):ABBPublicKey(pk.params,pk.a,(101,))
    with pytest.raises(SerializationError):ABBCiphertext(pk.params,pk.context,1,())
    with pytest.raises(SerializationError):ABBCiphertext(pk.params,pk.context,33,())


def test_role_confusion_and_large_length_rejected_before_matrix_allocation():
    raw=public().to_bytes()
    with pytest.raises(SerializationError):ABBCiphertext.from_bytes(raw)
    with pytest.raises(SerializationError):ABBPublicKey.from_bytes(MAGIC+b"\xff"*4)


def test_private_root_parent_leaf_and_failed_cache_are_strictly_restorable():
    pytest.importorskip("sage.all",reason="private equation restores require prescribed Sage")
    from experiments.research.chkp_basis import complete_kernel_basis
    from ibme.hibe.abb_rom.key_validation import expected_matrix
    pk=public()
    root=complete_kernel_basis(expected_matrix(pk,())).basis_rows
    first=complete_kernel_basis(expected_matrix(pk,(b"Bob",))).basis_rows
    second=complete_kernel_basis(expected_matrix(pk,(b"Bob",b"Alice"))).basis_rows
    leaf=ABBLevel2Key(pk,b"Bob",b"Alice",second)
    parent=ABBLevel1Key(pk,b"Bob",first,{b"Alice":leaf,b"Eve":None})
    master=ABBMasterSecret(pk,root,{b"Bob":parent,b"Carol":None})
    for value,kind in [(leaf,ABBLevel2Key),(parent,ABBLevel1Key),(master,ABBMasterSecret)]:
        raw=value.to_bytes()
        restored=kind.from_bytes(raw)
        assert restored.to_bytes()==raw
        assert "basis" not in repr(restored)
        for invalid in [raw[:-1],raw+b"x",raw+raw]:
            with pytest.raises(SerializationError):kind.from_bytes(invalid)
    loaded=ABBMasterSecret.from_bytes(master.to_bytes())
    assert loaded.parents[b"Carol"] is None
    assert loaded.parents[b"Bob"].children[b"Eve"] is None
    assert loaded.parents[b"Bob"].children[b"Alice"].parent_identity==b"Bob"
    # Deliberately public complete-basis fixtures, never real issued keys.


def test_private_decoder_rejects_wrong_context_equation_and_negative_zero():
    pytest.importorskip("sage.all",reason="private equation restores require prescribed Sage")
    from experiments.research.chkp_basis import complete_kernel_basis
    from ibme.hibe.abb_rom.key_validation import expected_matrix
    pk=public(); rows=complete_kernel_basis(expected_matrix(pk,())).basis_rows
    master=ABBMasterSecret(pk,rows)
    raw=master.to_bytes()
    ctx=raw.index(pk.context)
    with pytest.raises(SerializationError):ABBMasterSecret.from_bytes(raw[:ctx]+bytes([raw[ctx]^1])+raw[ctx+1:])
    bad=[list(row) for row in rows];bad[0][0]+=1
    broken=ABBMasterSecret(pk,tuple(tuple(row) for row in bad))
    with pytest.raises(SerializationError):ABBMasterSecret.from_bytes(broken.to_bytes())
    # Zero is encoded as sign0/LP(00); force sign1 at a zero coefficient.
    pos=raw.index(pk.context)+64
    for row in rows:
        for value in row:
            size=max(1,(abs(value).bit_length()+7)//8)
            if value==0:
                corrupt=raw[:pos]+b"\x01"+raw[pos+1:]
                with pytest.raises(SerializationError):ABBMasterSecret.from_bytes(corrupt)
                return
            pos+=5+size
    raise AssertionError("fixture must include a zero entry")
