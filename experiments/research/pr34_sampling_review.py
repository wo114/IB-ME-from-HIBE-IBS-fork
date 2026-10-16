"""Local, fixed-source PR34 sampler diagnostics using disposable test keys.

Reports ranks, equality checks and exact public modulo-bias probabilities.
Does not export keys, recover a key, forge signatures or contact a service.
The reviewed implementation is loaded only from the explicitly pinned tree.
"""

import argparse
from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path
import platform
import re
import subprocess
import sys


REVIEWED_HEAD = "20d75e9b9dcf2ceb8509cedd867a5c479e03af62"
REVIEWED_FILES = ("algebra.py", "backend.py", "hashing.py", "config.py", "objects.py")


def modulo_bias(q):
    """Exact TV of a byte-aligned uniform integer reduced modulo q."""
    if type(q) is not int or not 3 <= q < 2**256:
        raise ValueError("bounded exact modulus required")
    width = (q.bit_length()+7)//8
    span = 2**(8*width)
    remainder = span % q
    return dict(modulus=q, input_bytes=width, heavy_residues=remainder,
        scalar_TV_from_uniform=str(Fraction(remainder*(q-remainder), span*q)))


def inspect_source(source_root):
    source_root = Path(source_root).resolve(strict=True)
    command = ["git", "-C", str(source_root)]
    pointer = source_root/".git"
    if sys.platform == "linux" and pointer.is_file():
        gitdir = pointer.read_text(encoding="utf-8").strip().removeprefix("gitdir: ")
        if re.match(r"^[A-Za-z]:[/\\]", gitdir):
            # A Windows-managed worktree cannot be resolved by Linux git's -C.
            translated = subprocess.check_output(["wslpath", "-u", gitdir], text=True).strip()
            command = ["git", "--git-dir", translated, "--work-tree", str(source_root)]
    def git(*args):
        return subprocess.check_output([*command, *args], text=True).strip()
    if git("rev-parse", "HEAD") != REVIEWED_HEAD:
        raise ValueError("this diagnostic is restricted to the reviewed PR34 head")
    relative = "experiments/research/candidates/sageloli"
    if git("status", "--porcelain", "--", relative):
        raise ValueError("reviewed source files must be unchanged")
    return source_root, {name: sha256((source_root/relative/name).read_bytes()).hexdigest()
                         for name in REVIEWED_FILES}


def inspect_test_keys(source_root):
    root, hashes = inspect_source(source_root)
    sys.path[:0] = [str(root/"src"), str(root)]
    from sage.all import QQ, matrix
    from sage.version import version as sage_version
    from ibme.core.randomness import DeterministicRandom
    from experiments.research.candidates.sageloli import (
        SISBackend, SISParams, RSISBackend, RSISParams,
    )
    import experiments.research.candidates.sageloli.algebra as algebra
    if not Path(algebra.__file__).resolve().is_relative_to(root):
        raise ValueError("foreign Sageloli provider")
    results = []
    for route, factory, params in (("sis", SISBackend, SISParams()),
                                   ("rsis", RSISBackend, RSISParams())):
        for repetition in range(3):
            backend = factory(rng=DeterministicRandom(
                f"local-review-{route}-{repetition}".encode("ascii")))
            public, master = backend.setup(params)
            issued = backend.key_extract(master, b"test-user")
            restored = type(issued).from_bytes(issued.to_bytes())
            width = params.nk if route == "sis" else params.d*params.k
            t = matrix(QQ, restored.trapdoor)
            top, bottom = t[:-width, :], t[-width:, :]
            relation = top == matrix(QQ, master.trapdoor)*bottom
            rank = int(bottom.rank())
            # Only rank and a zero-residual predicate leave this function.
            results.append(dict(route=route, repetition=repetition,
                dimensions=([params.n, params.k, params.m] if route == "sis"
                            else [params.d, params.k, params.l]),
                q=params.q, identity_bytes=9, issued_key_roundtrip=True,
                bottom_rows=width, bottom_rank=rank,
                exact_root_times_bottom_equals_top=relation,
                root_uniquely_determined_by_one_issued_test_key=relation and rank == width))
    return dict(schema="PR34-LOCAL-SAMPLER-REVIEW/1", reviewed_head=REVIEWED_HEAD,
        reviewed_source_sha256=hashes, checks=results,
        modulo_bias=[modulo_bias(81), modulo_bias(19683)],
        test_randomness="DeterministicRandom, disposable local teaching keys only",
        network_operations=0, recovered_keys=0, forged_signatures=0,
        private_values_exported=False,
        environment=dict(python=sys.version.split()[0], sage=sage_version,
                         platform=platform.platform()),
        security_claim="none", backend_admitted=False, parameters_are_formal=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = inspect_test_keys(args.source_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(f"{len(result['checks'])} local rank checks; no private values exported")


if __name__ == "__main__":
    main()
