"""Reduce the pinned official Falcon round-3 KATs to public test receipts.

AES CTR-DRBG is ONLY the official deterministic test entropy generator.
It never supplies production key generation or signing randomness.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import zipfile

ARCHIVE_SHA256="d625407dbda9e5835f610aaeba1147e029988a6610e0107dfd292033138e1d47"


class TestDRBG:
    def __init__(self,seed):
        self.key=bytes(32);self.counter=0;self.update(seed)

    def block(self):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        self.counter=(self.counter+1)%(1<<128)
        encryptor=Cipher(algorithms.AES(self.key),modes.ECB()).encryptor()
        return encryptor.update(self.counter.to_bytes(16,"big"))+encryptor.finalize()

    def update(self,data=None):
        value=b"".join(self.block() for _ in range(3))
        if data is not None:value=bytes(a^b for a,b in zip(value,data,strict=True))
        self.key=value[:32];self.counter=int.from_bytes(value[32:],"big")

    def read(self,size):
        value=b"".join(self.block() for _ in range((size+15)//16))[:size]
        self.update();return value


def generate(archive):
    assert hashlib.sha256(archive.read_bytes()).hexdigest()==ARCHIVE_SHA256
    vectors=[];files={}
    with zipfile.ZipFile(archive) as source:
        for degree,logn,target in ((512,9,666),(1024,10,1280)):
            name=f"falcon-round3/KAT/falcon{degree}-KAT.rsp"
            raw=source.read(name);files[name]=hashlib.sha256(raw).hexdigest()
            for block in raw.decode("ascii").split("\n\n"):
                fields=dict(line.split(" = ",1) for line in block.splitlines() if " = " in line)
                if not fields:continue
                b=lambda key:bytes.fromhex(fields[key])
                msg=b("msg");sm=b("sm");mlen=int(fields["mlen"])
                assert len(msg)==mlen and len(sm)==int(fields["smlen"])
                assert sm[42:42+mlen]==msg and sm[42+mlen]==0x20+logn
                assert int.from_bytes(sm[:2],"big")==len(sm)-42-mlen
                signature=bytes([0x30+logn])+sm[2:42]+sm[43+mlen:]
                rng=TestDRBG(b("seed"));keyseed=rng.read(48);nonce=rng.read(40);signseed=rng.read(48)
                assert nonce==sm[2:42]
                padded=signature+bytes(max(0,target-len(signature)))
                vectors.append(dict(degree=degree,count=int(fields["count"]),message=msg.hex(),
                    key_seed=keyseed.hex(),nonce=nonce.hex(),sign_seed=signseed.hex(),
                    pk_sha256=hashlib.sha256(b("pk")).hexdigest(),sk_sha256=hashlib.sha256(b("sk")).hexdigest(),
                    compressed_bytes=len(signature),signature_sha256=hashlib.sha256(signature).hexdigest(),
                    padded_sha256=hashlib.sha256(padded).hexdigest() if len(signature)<=target else None))
    assert len(vectors)==200
    return dict(source_url="https://falcon-sign.info/falcon-round3.zip",archive_sha256=ARCHIVE_SHA256,
        source_files_sha256=files,entropy="official TEST AES256 CTR-DRBG, not production",vectors=vectors)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive",type=Path);parser.add_argument("output",type=Path)
    args=parser.parse_args();data=generate(args.archive)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    raw=gzip.compress(json.dumps(data,sort_keys=True,separators=(",",":")).encode(),mtime=0)
    args.output.write_bytes(raw)
    print(json.dumps(dict(vectors=len(data["vectors"]),sha256=hashlib.sha256(raw).hexdigest(),
        padded_fit=sum(v["padded_sha256"] is not None for v in data["vectors"]),
        source_files_sha256=data["source_files_sha256"])))


if __name__=="__main__":main()
