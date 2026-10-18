"""Summarize only PUBLIC receipts; preserve full data in deterministic gzip.

Usage: python analyze.py <reclassified.json> <output-directory> <environment.json> <original-screen.json>
Plots compare necessary byte counts and heuristic model costs, never runtime
or security levels. No state, key or random source is read.
"""

from collections import Counter
import gzip
from hashlib import sha256
import json
from math import isfinite
from pathlib import Path
import sys


def minimum(row):
    costs = [entry for role in row["estimator_results"].values() for entry in role.values()]
    if len(costs) != 8 or any(x["status"] != "finite_estimate" or x["rop_log2"] is None
                            or not isfinite(x["rop_log2"]) for x in costs):
        return None
    return min(x["rop_log2"] for x in costs)


def item(row):
    g, r = row["complete_group"], row["resources"]
    return dict(n=g["n"], radix_bits=g["radix_bits"], base=g["base"], q=str(g["q"]),
        q_bits=g["q_bits"], gadget_digits=g["gadget_digits"],
        w=g["w"], m=g["m"], parent_sample_dimension=g["parent_sample_dimension"], leaf_dimension=g["leaf_dimension"],
        minimum_comparison_log2_rop=minimum(row),
        role_minimum_log2_rop=row["decision"]["role_minimum_log2_rop"],
        conditional_probability_met=row["finite_projection"]["target_lifetime_met"],
        conditional_probability_upper=row["finite_projection"].get("modeled_lifetime_upper"),
        scalar_profile_met=r["current_scalar_width_domain"],
        parent_R_entries=r["parent_R_entries"],
        parent_R_encoded_bytes=r["matrix_component_bytes"]["parent_R"],
        persistent_payload_floor_bytes=r["persistent_matrix_payload_floor_bytes"],
        probe_payload_floor_bytes=r["current_probe_live_matrix_payload_floor_bytes"],
        parent_proposal_scalar_draws_at_least=r["parent_proposal_scalar_draws_at_least"],
        parent_final_Rz_logical_scalar_products=2*g["n"]*g["w"]**2,
        leaf_256_final_Rz_logical_scalar_products=256*r["parent_R_entries"],
        decision=row["decision"]["status"], deployment_status=row["decision"]["deployment_status"],
        parameter_screen_candidate=row["decision"]["parameter_screen_candidate"],
        actual_seconds=None, actual_RSS_bytes=None)


def main(source, output, environment, original):
    raw = source.read_bytes()
    data = json.loads(raw)
    if (data["status"] != "completed_public_screen" or data.get("estimator", {}).get("completed") is not True
            or data.get("reclassification", {}).get("policy") != "hardware-budget-advisory/1"):
        raise ValueError("a completed public screen reclassified with advisory hardware budgets is required")
    rows = data["rows"]
    output.mkdir(parents=True, exist_ok=True)
    compressed = gzip.compress(raw, mtime=0)
    (output/"screen.json.gz").write_bytes(compressed)
    original_bytes = original.read_bytes()
    if sha256(original_bytes).hexdigest() != data["reclassification"]["input_sha256"]:
        raise ValueError("original screen hash differs from the reclassification input")
    original_gzip = gzip.compress(original_bytes, mtime=0)
    (output/"original-screen.json.gz").write_bytes(original_gzip)
    eligible = [row for row in rows if row["decision"]["parameter_screen_candidate"]]
    fit = [row for row in rows if row["resources"]["necessary_payload_fits_research_budget"]]
    models = [entry for row in rows for role in row["estimator_results"].values() for entry in role.values()]
    # Hardware snapshots are recorded separately in environment.json. These
    # thresholds expose the effect of the 8 GiB engineering choice; they do
    # not grant all machine RAM to a process or include omitted overhead.
    host = json.loads(environment.read_bytes())
    budgets = {"declared_research_8GiB": data["resident_budget_bytes"],
               **{f"deployment_{gib}GiB":gib*2**30 for gib in (16,32,64,128)},
               "snapshot_WSL_total": host["wsl_mem_total_bytes"],
               "snapshot_Windows_physical_total": host["windows_physical_memory_bytes"]}
    summary = dict(schema="CHKP-3M-RADIX-SCREEN-SUMMARY/1", status="completed", source_commit=data["source_commit"],
        reclassification=data["reclassification"], hardware_budget_is_advisory=True,
        source_json_sha256=sha256(raw).hexdigest(), source_json_bytes=len(raw),
        environment_sha256=sha256(environment.read_bytes()).hexdigest(),
        compressed_sha256=sha256(compressed).hexdigest(), compressed_bytes=len(compressed),
        original_compressed_sha256=sha256(original_gzip).hexdigest(), original_compressed_bytes=len(original_gzip),
        groups=len(rows), dimensions=data["dimensions"], radix_bits=data["radix_bits"],
        estimator_calls=len(models), estimator_status=dict(Counter(x["status"] for x in models)),
        finite_profile_status=dict(Counter(row["finite_projection"]["status"] for row in rows)),
        decisions=dict(Counter(row["decision"]["status"] for row in rows)),
        necessary_payload_fit_groups=len(fit),
        highest_minimum_comparison_cost_among_payload_fit=max((minimum(row) for row in fit if minimum(row) is not None), default=None),
        cost_and_scalar_and_conditional_probability_pass_groups=len(eligible),
        parameter_screen_candidates_by_dimension=dict(Counter(row["n"] for row in eligible)),
        budget_sensitivity={name:dict(bytes=budget,
            cost_scalar_probability_and_probe_payload_floor_pass=sum(row["resources"]["current_probe_live_matrix_payload_floor_bytes"] <= budget for row in eligible),
            actual_runtime_admitted=False) for name,budget in budgets.items()},
        smallest_payload_model_eligible=(item(min(eligible, key=lambda row:row["resources"]["current_probe_live_matrix_payload_floor_bytes"])) if eligible else None),
        candidates=[item(row) for row in sorted(eligible, key=lambda row:row["resources"]["current_probe_live_matrix_payload_floor_bytes"])],
        table=[item(row) for row in rows], key_generations=0, sampler_calls=0, entropy_reads=0,
        security_claim="none", backend_admitted=False, parameters_are_formal=False)
    (output/"summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(10.5, 6.2))
    fig.subplots_adjust(bottom=0.20, right=0.97, top=0.91)
    palette = plt.get_cmap("viridis", len(data["dimensions"]))
    for index, n in enumerate(data["dimensions"]):
        group = [row for row in rows if row["n"] == n and minimum(row) is not None]
        good = [row for row in group if row["resources"]["current_scalar_width_domain"]]
        bad = [row for row in group if not row["resources"]["current_scalar_width_domain"]]
        for subset, marker, alpha, label in ((good,"o",0.75,f"n={n}"), (bad,"x",0.4,None)):
            ax.scatter([row["resources"]["current_probe_live_matrix_payload_floor_bytes"]/2**30 for row in subset],
                [minimum(row) for row in subset],s=20,c=[palette(index)],marker=marker,alpha=alpha,label=label)
    ax.set_xscale("log")
    ax.axvline(data["resident_budget_bytes"]/2**30,color="#b14e26",linestyle="--",linewidth=1)
    ax.axhline(data["cost_floor"],color="#b14e26",linestyle="--",linewidth=1)
    ax.set(xlabel="Current-probe live matrix payload floor (GiB; overhead excluded)",
        ylabel="Minimum log2(rop) across eight comparison-model estimates",
        title="CHKP full-3m: parameter candidates are independent of hardware budgets")
    ax.grid(alpha=0.2)
    ax.legend(ncol=3,fontsize=8,loc="upper left")
    highlighted = next(row for row in rows if row["n"] == 4096 and row["complete_group"]["radix_bits"] == 12)
    x = highlighted["resources"]["current_probe_live_matrix_payload_floor_bytes"]/2**30
    ax.scatter([x], [minimum(highlighted)], s=150, facecolors="none", edgecolors="#b14e26", linewidths=1.5)
    ax.annotate("Retained: n=4096, b=4096\n19.20 GiB probe payload; model 128.79",
                (x, minimum(highlighted)), xytext=(25,35), textcoords="offset points", fontsize=8,
                arrowprops=dict(arrowstyle="->", color="#b14e26"))
    fig.text(0.5,0.07,"Vertical dash: advisory 8 GiB deployment budget. Horizontal dash: model threshold 128, not security bits.",
             ha="center",fontsize=8)
    fig.text(0.5,0.035,"Crosses: scalar profile needs extension. Missing/error estimates excluded from plot, retained in data. No high-dimensional run measured.",
             ha="center",fontsize=8)
    fig.savefig(output/"resource-cost.png",dpi=180)
    fig.savefig(output/"resource-cost.svg")
    svg = output/"resource-cost.svg"
    svg.write_text("\n".join(line.rstrip() for line in svg.read_text(encoding="utf-8").splitlines())+"\n", encoding="utf-8")
    plt.close(fig)
    print(json.dumps({k:v for k,v in summary.items() if k not in ("table","candidates")},indent=2))


if __name__ == "__main__": main(*(Path(arg) for arg in sys.argv[1:5]))
