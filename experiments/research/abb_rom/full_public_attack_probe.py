"""Public-only n=1 attack on the actual complete byte ABB encryption API.

Read public.bin exclusively; never load a master, parent or leaf. The known
32 B test plaintext is encrypted with default system noise/randomness. Archive
only equality/length/count observations, not seeds, vectors or recovered bits.
"""
import argparse
import json
from pathlib import Path
from time import perf_counter
from fractions import Fraction

from ibme.hibe.abb_rom import ABBROMHIBE,ABBPublicKey,ABBBitPublic,ABBBitCiphertext,ABBBitEncryptor
from ibme.hibe.abb_rom.key_validation import expected_matrix
from experiments.attacks.abb_small_dimension import recover_n1_bit
from .hibe_probe import paths,CountedSystemEntropy,source_fingerprints


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--public-key-file',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    if args.output.exists():raise FileExistsError('fresh attack receipt required')
    public=ABBPublicKey.from_bytes(args.public_key_file.read_bytes())
    if public.params.n!=1:raise ValueError('this specific attack requires n=1')
    before=source_fingerprints();started=perf_counter();source=CountedSystemEntropy()
    rcv,phi=paths();message=bytes(range(32))
    ciphertext=ABBROMHIBE().encrypt(public,rcv,phi,message,rng=source)
    bit_public=ABBBitPublic(expected_matrix(public,(rcv,phi)),public.u0)
    radius=ABBBitEncryptor(bit_public,Fraction(4,public.params.q)).noise.radius
    expected=[(byte>>shift)&1 for byte in message for shift in reversed(range(8))]
    results=[]
    for block,bit in zip(ciphertext.blocks,expected,strict=True):
        attack=recover_n1_bit(bit_public,ABBBitCiphertext(block[0],tuple(block[1:])),radius)
        results.append(attack['candidate_bits']==[bit])
    record=dict(schema='ABB-FULL-BYTE-PUBLIC-N1-ATTACK/1',status='passed' if all(results) else 'failed',
        params=public.params.to_record(),payload_bytes=32,identity_bytes=[86,86],actual_noisy_bits=len(results),
        all_256_original_bits_unique=all(results),new_roots=0,new_private_keys=0,
        private_key_files_loaded=0,new_encryptions=1,attack_uses_only_public_inputs=True,
        encryption_rng='default counted system CSPRNG',encryption_entropy_bytes=source.bytes_used,
        attacker_entropy_bytes=0,seconds=perf_counter()-started,source_sha256_before=before,
        source_sha256_after=source_fingerprints(),security_claim='none',backend_admitted=False,parameters_are_formal=False)
    record['source_unchanged_during_execution']=record['source_sha256_before']==record['source_sha256_after']
    if not record['source_unchanged_during_execution']:record['status']='failed-source-changed'
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({key:record[key] for key in ('status','actual_noisy_bits','all_256_original_bits_unique','seconds')}))
    return 0 if record['status']=='passed' else 1


if __name__=='__main__':raise SystemExit(main())
