"""Bounded public attacks on the SMALL study domain, not a general break."""
from dataclasses import replace
from .objects import Signature,Public
from .hashing import frame,XOF,uniform,challenge_count,challenge_hash
from .verification import verify


def modulus_shift(public,identity,message,signature):
    """Try a different valid signature for the same pair using only q and z."""
    for i in range(public.params.n):
        for sign in (1,-1):
            z=list(signature.z1);z[i]+=sign*public.params.q
            candidate=replace(signature,z1=tuple(z))
            if candidate!=signature and verify(public,identity,message,candidate):return candidate
    return None


def zero_challenge_forgery(public,*,max_trials=2**22):
    """Search H'(0,msg)=0. Fully public; an absent witness proves nothing."""
    if type(public) is not Public or type(max_trials) is not int or not 1<=max_trials<=2**22:
        raise ValueError("public attack budget")
    p=public.params;zero=(0,)*p.n;count=challenge_count(p.n,p.challenge_weight)
    if p.message_bytes<19:raise ValueError("attack diagnostic requires 19 message bytes")
    # Cache the fixed public prefix; identical to challenge_hash's framing.
    prefix=frame(b"XIE-STUDY/CHALLENGE/1",public.context,bytes(4*p.n))
    for trial in range(max_trials):
        message=b"public-forgery/"+trial.to_bytes(4,"big")
        source=XOF(prefix+frame(message))
        if uniform(source,count)==0:
            assert challenge_hash(public,zero,message)==zero
            signature=Signature(public.context,zero,zero,zero)
            assert verify(public,b"A",message,signature) and verify(public,b"B",message,signature)
            return dict(status="witness_found",trials=trial+1,challenge_space=count,message_hex=message.hex(),
                signature_hex=signature.to_bytes().hex(),two_unissued_identities_accepted=True,
                private_material_used=False)
    return dict(status="budget_exhausted",trials=max_trials,challenge_space=count,private_material_used=False,
                absence_is_not_security_evidence=True)
