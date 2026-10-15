"""Generate own PUBLIC TEST vectors, not official Xie test vectors."""
import json
from pathlib import Path


def main():
    from ibme.core.randomness import DeterministicRandom
    from .params import StudyParams
    from .runtime import setup,sign
    from .verification import verify
    records=[]
    for n in (16,32):
        rng=DeterministicRandom(b"XIE-EQUATION-STUDY PUBLIC TEST VECTOR/"+bytes([n]))
        public,master=setup(StudyParams(n=n),rng=rng)
        identity=b"public-test-identity";message=b"own corrected Xie TEST vector\0"+bytes([n])
        key=master.extract(identity,rng=rng);signature=sign(key,message,rng=rng)
        assert verify(public,identity,message,signature)
        records.append(dict(n=n,public_hex=public.to_bytes().hex(),identity_hex=identity.hex(),
            message_hex=message.hex(),signature_hex=signature.to_bytes().hex()))
    output=Path("tests/fixtures/xie_study/public.json");output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(dict(kind="own PUBLIC TEST vectors, not official",private_material=False,
        security_claim="none",vectors=records),indent=2)+"\n",encoding="utf-8")
    print(json.dumps(dict(status="generated",vectors=2,private_material=False)))


if __name__=="__main__":main()
