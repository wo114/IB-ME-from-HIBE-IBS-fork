"""Read retained real public components and archive the n=1 negative control."""

import argparse
import json
from pathlib import Path
from time import perf_counter

from ibme.hibe.abb_rom import ABBBitPublic, ABBBitCiphertext, ABBBitEncryptor
from ibme.lattice.research import ModMatrixReference
from experiments.attacks.abb_small_dimension import recover_n1_bit
from fractions import Fraction


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--saved-private-directory", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    saved = Path(args.saved_private_directory)
    output = Path(args.output)
    if output.exists():
        raise FileExistsError("new public receipt required")
    if not (saved / "completed").is_file() or (saved / "pending").exists():
        raise ValueError("completed retained experiment required")
    # The retained probe file also has a basis; the attack receives exclusively
    # its PUBLIC projection. Neither that field nor a decryption sampler is used.
    data = json.loads((saved / "root-private.json").read_text(encoding="utf-8"))
    public = ABBBitPublic(ModMatrixReference(data["a"], data["params"]["q"]), data["u0"])
    del data
    ciphertexts = [ABBBitCiphertext(**item) for item in json.loads(
        (saved / "ciphertexts-private.json").read_text(encoding="utf-8"))]
    radius = ABBBitEncryptor(public, Fraction(4, public.matrix.q)).noise.radius
    started = perf_counter()
    checks = []
    for index, (ct, actual_bit) in enumerate(zip(ciphertexts, [0, 1, 1, 0, 1, 0, 0, 1], strict=True)):
        result = recover_n1_bit(public, ct, radius)
        candidate_bits = result.pop("candidate_bits")
        result["actual_bit_is_candidate"] = actual_bit in candidate_bits
        result["unique_actual_bit"] = candidate_bits == [actual_bit]
        result["index"] = index
        checks.append(result)
    receipt = {"schema": "ABB-REAL-ROOT-N1-PUBLIC-ATTACK/1", "n": 1,
        "q": str(public.matrix.q), "dimension": public.matrix.ncols,
        "noise_radius": radius, "seconds": perf_counter() - started,
        "actual_ciphertexts": len(ciphertexts), "checks": checks,
        "all_actual_bits_unique": all(item["unique_actual_bit"] for item in checks),
        "new_root_generations": 0, "new_encryptions": 0, "entropy_bytes": 0,
        "attack_function_uses_only_public_input": True,
        "input_loader_projects_public_fields_from_retained_probe_artifact": True,
        "security_claim": "none", "backend_admitted": False}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"actual_ciphertexts": len(ciphertexts),
                      "all_actual_bits_unique": receipt["all_actual_bits_unique"]}))
    return 0 if receipt["all_actual_bits_unique"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
