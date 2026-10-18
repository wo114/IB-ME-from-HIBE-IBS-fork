"""Exact compact byte counts for EXISTING complete 3m target projections.

Public arithmetic only. Constructs scalar radius certificates, never target
matrices, keys or samples. Does not change targets or re-estimate security.
"""

import argparse
import json
from math import isqrt
from pathlib import Path

from ibme.lattice.matrix_sampling.packed import coordinate_bytes, MAGIC
from ibme.lattice.matrix_sampling.scalar import MatrixFiniteGaussian, MatrixFiniteOptions


def project(group):
    n, q, w, m = (group[k] for k in ("n", "q", "w", "m"))
    parent_dim = group["parent_sample_dimension"]
    parent_width = group["parent_width_squared"]
    leaf_dim, leaf_width = group["leaf_dimension"], group["leaf_width_squared"]
    if (w != n*(q-1).bit_length() or m != 2*n+w or parent_dim != 2*m-w or leaf_dim != 3*m):
        raise ValueError("expected complete author-manuscript 3m target group")
    options = MatrixFiniteOptions(tail_bits=192, gaussian_abort_bits=192,
        mass_bits=320, precision_bits=384, max_uniform_trials=256)
    root_scalar = MatrixFiniteGaussian(group["root_r_squared"], group["root_r_squared"], options=options)
    header = len(MAGIC)+41
    public_width = coordinate_bytes(q-1, False)
    parent_coordinate_bound = isqrt(parent_dim*parent_width)
    parent_bytes = coordinate_bytes(parent_coordinate_bound, True)
    r_entries = parent_dim*w
    return dict(n=n, q=str(q), modulus_bits=q.bit_length(), source_dimensions="author-manuscript CHKP 3m",
        root_R_entries=2*n*w, parent_R_entries=r_entries,
        root_R_coordinate_bytes=coordinate_bytes(root_scalar.radius, True),
        parent_R_coordinate_bytes=parent_bytes, parent_R_coordinate_bound=str(parent_coordinate_bound),
        root_R_packed_bytes=header+2*n*w*coordinate_bytes(root_scalar.radius, True),
        parent_R_packed_bytes=header+r_entries*parent_bytes,
        parent_R_old_JSON_optimistic_minimum_bytes=2*r_entries,
        public_root_packed_bytes=header+n*m*public_width,
        parent_public_packed_bytes=header+n*2*m*public_width,
        one_fixed_leaf_256_packed_bytes=header+256*leaf_dim*coordinate_bytes(isqrt(leaf_dim*leaf_width), True),
        old_leaf_dense_Schur_entries=(leaf_dim-w)**2, new_dense_Schur_entries=0,
        current_prototype_parent_entry_gate=r_entries <= 2**24,
        current_prototype_parent_R_byte_gate=header+r_entries*parent_bytes <= 512*2**20,
        actual_target_root_or_parent_or_leaf_executed=False, peak_RSS=None, runtime_seconds=None,
        encoded_bytes_are_not_RSS=True, security_claim="none", backend_admitted=False, parameters_are_formal=False)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--existing-targets", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    original = json.loads(args.existing_targets.read_bytes())
    result = dict(schema="MP12-BLOCKED-3M-BYTE-PROJECTION/1",
        existing_source=str(args.existing_targets), rows=[project(row["complete_group"]) for row in original["rows"]],
        experiments_executed=0, new_security_estimates=0, retained_existing_target_parameters=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True)+"\n", encoding="utf-8")


if __name__ == "__main__": main()
