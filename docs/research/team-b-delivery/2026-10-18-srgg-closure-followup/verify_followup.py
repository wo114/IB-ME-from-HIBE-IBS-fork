"""Check byte integrity and claim boundaries of this local SRGG WIP package."""
from hashlib import sha256
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def file_at(name):
    require(type(name) is str and name and "\\" not in name, "noncanonical manifest path")
    path = Path(name)
    require(not path.is_absolute() and all(part not in ("", ".", "..") for part in path.parts),
            "unsafe manifest path")
    resolved = (ROOT / path).resolve()
    require(ROOT == resolved or ROOT in resolved.parents, "manifest path escapes repository")
    require(resolved.is_file(), "missing package file: " + name)
    return resolved


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def receipt(name):
    return json.loads((HERE / name).read_text(encoding="utf-8"))


def main():
    manifest = receipt("MANIFEST.json")
    require(manifest.get("schema") == "IBME/SRGG-CLOSURE-FOLLOWUP-MANIFEST/1",
            "manifest schema")
    entries = manifest.get("entries")
    require(type(entries) is dict and len(entries) >= 16, "manifest coverage")
    for name, expected in entries.items():
        require(type(expected) is dict and set(expected) == {"bytes", "sha256"},
                "manifest entry structure")
        path = file_at(name)
        require(path.stat().st_size == expected["bytes"] and digest(path) == expected["sha256"],
                "package byte mismatch: " + name)

    numerical = receipt("schur-fixed-root-numerical-normalizer.json")
    require(numerical["schema"] == "IBME/SRGG-SCHUR-FIXED-ROOT-NUMERICAL-RECEIPT/1",
            "numerical receipt schema")
    require(digest(file_at(numerical["paper"]["path"])) == numerical["paper"]["sha256"],
            "frozen paper")
    for name, expected in numerical["source_sha256"].items():
        require(digest(file_at(name)) == expected, "numerical source drift: " + name)
    rows = numerical["rows"]
    require(len(rows) == 6, "six original rows and interpretations")
    expected_profiles = ["PARAM-I", "PARAM-II", "PARAM-III"]
    for index, row in enumerate(rows):
        require(row["profile"] == expected_profiles[index // 2], "profile order")
        require(row["interpretation"] == (
            "table-standard-deviation" if index % 2 == 0 else "literal-density-width"),
            "interpretation order")
        require(row["setup_attempts"] >= 1 and row["extraction_calls"] == 1,
                "actual root and extraction")
        require(row["private_material_exported"] is False and
                row["full_source_schur_integer_tv_including_abort"] is None,
                "numerical claim boundary")
        for phase in ("master", "signature"):
            local = row[phase]
            ideal = row[phase + "_ideal_normalizer"]
            require(local["all_ideal_schur_pivot_eigenvalues_at_least_64"] is True,
                    "fixed-root pivot floor")
            require(local["full_target_integer_tv_upper_including_abort"] is None,
                    "finite implementation TV remains open")
            require(ideal["ideal_pivot_density_shape_lower"] == 64 and
                    ideal["ideal_sequential_vs_joint_integer_tv_dyadic_bits"] >= 276 and
                    ideal["source_schur_finite_output_tv_upper"] is None and
                    ideal["all_setup_roots_covered"] is False,
                    "ideal-only normalizer scope")

    setup = receipt("setup-conditioning.json")
    require(setup["schema"] == "IBME/SRGG-PAPER-SETUP-CONDITIONING-PREFLIGHT/1",
            "setup receipt schema")
    require([row["profile"] for row in setup["rows"]] == expected_profiles,
            "setup original rows")
    for row, bits in zip(setup["rows"], (6371, 15031, 27375)):
        require(row["matrix_bernstein"]["failure_upper"] == "1" and
                row["sparse_l1_alternative"]["dyadic_bits"] == bits and
                row["runtime_success_probability_or_abort_budget"] is None and
                row["accepted_setup_root_distribution_bound"] is None,
                "setup probability boundary")
    ring = receipt("ring-crt-31sq.json")
    require((ring["prime"], ring["modulus"], ring["degree"], ring["factor_count"])
            == (31, 961, 512, 16), "actual 31-square ring")
    require(ring["idempotents_pairwise_project_and_sum_to_one"] is True and
            ring["public_polynomial_crt_reconstruction"] is True and
            ring["actual_attack_cost"] is None, "CRT scope")
    for item in (numerical, setup, ring):
        require(item["security_claim"] == "none" and
                item["backend_admitted"] is False and
                item["parameters_are_formal"] is False and
                item["nist_security_category"] is None,
                "no formal security admission")
    print(json.dumps({"status": "verified", "manifest_entries": len(entries),
                      "fixed_roots": len(rows), "ring_factors": ring["factor_count"],
                      "security_claim": "none"}, sort_keys=True))


if __name__ == "__main__":
    main()
