"""Publication figure from recorded observations; no cryptographic operations."""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = Path(__file__).resolve().parent
report = json.loads((HERE / "placement.json").read_bytes())
variants = ("source", "windows_wheel", "wsl_wheel")
labels = ("Source\nWindows mount", "Same wheel\nWindows mount", "Same wheel\nWSL filesystem")
colors = ("#2563eb", "#d97706", "#0f766e")
fig, axes = plt.subplots(1, 2, figsize=(10.5, 4.6), layout="constrained")
for axis, operation in zip(axes, ("encrypt", "decrypt")):
    data = [[1000*t for t in report["timing_seconds"][variant][operation]["observations"]] for variant in variants]
    boxes = axis.boxplot(data, patch_artist=True, widths=0.45, showfliers=True,
                         medianprops=dict(color="#111827", linewidth=1.7))
    for box in boxes["boxes"]:
        box.set_facecolor("#e5e7eb")
        box.set_edgecolor("#9ca3af")
    for state, color in enumerate(colors):
        values = [1000*report["per_state_median_seconds"][variant][operation][state] for variant in variants]
        axis.plot((1, 2, 3), values, "o-", color=color, linewidth=1.2, markersize=4,
                  label=f"State {state+1} median")
    axis.set_xticks((1, 2, 3), labels)
    axis.set_title("Complete " + operation)
    axis.set_ylabel("Time (ms)")
    axis.set_ylim(bottom=0)
    axis.grid(axis="y", alpha=0.2)
    axis.spines[["top", "right"]].set_visible(False)
axes[1].legend(loc="upper right", fontsize=8)
fig.suptitle("Identical LATTE + ML-DSA-44 suite: code placement ablation", fontsize=12)
fig.supxlabel("3 independent states; 10 observations per state and placement. Setup, imports and restore excluded.", fontsize=8)
fig.savefig(HERE / "timing.png", dpi=170)
fig.savefig(HERE / "timing.svg")
plt.close(fig)
# Matplotlib emits spaces before SVG path line breaks. Strip those without
# changing coordinates so regenerated artifacts pass git diff --check.
svg = HERE / "timing.svg"
svg.write_text("\n".join(line.rstrip() for line in svg.read_text(encoding="utf-8").splitlines()) + "\n", encoding="utf-8")
