"""Run with Sage python -I: installed directory, saved real root, public receipt."""
from pathlib import Path
import sys
import json
import os

target, rootfile, output = map(lambda s: Path(s).resolve(), sys.argv[1:])
sys.path.insert(0, str(target))
os.environ.pop("IBME_EXACT_GRAM_EXECUTABLE", None)
os.environ.pop("IBME_QFALL_PRIVATE_ENGINE", None)
from ibme.lattice.matrix_sampling import mp12_structured as tool
from ibme.lattice.matrix_sampling import scalar, gpv
from ibme.lattice.chkp import basis, entropy
from ibme.core import randomness

providers = [tool, scalar, gpv, basis, entropy, randomness]
assert all(Path(p.__file__).resolve().is_relative_to(target) for p in providers)
root = tool.StructuredTrapdoor.from_bytes(rootfile.read_bytes())
assert root.to_bytes() == rootfile.read_bytes()
sampler = tool.StructuredPreimageSampler(root)
sample = sampler.sample((7, 11), rng=randomness.DeterministicRandom(b"isolated-installed-structured-sample"))
assert tuple(sum(a*b for a, b in zip(row, sample)) % root.q for row in root.public.rows) == (7, 11)
report = dict(status="passed", isolated_interpreter=True,
    providers={p.__name__: str(Path(p.__file__).resolve().relative_to(target)) for p in providers},
    n=root.n, q=root.q, total_dimension=root.dimension,
    rng="explicit deterministic TEST entropy; saved real root reused",
    full_kernel_bases_expanded=0, native_Gram_qFALL_dependencies_configured=False,
    security_claim="none", backend_admitted=False, parameters_are_formal=False)
output.write_text(json.dumps(report, indent=2)+"\n")
print("Installed-only structured consumer and saved-key sample passed")
