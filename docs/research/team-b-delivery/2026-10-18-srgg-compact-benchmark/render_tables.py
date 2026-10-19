"""Rebuild public CSV/Markdown summaries from the frozen benchmark JSON."""
import csv
import io
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def csv_text(header, rows):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(header)
    writer.writerows(rows)
    return stream.getvalue()


def render(report):
    wire, times, memory = [], [], []
    markdown = ["# Generated SRGG summaries", "", "Medians across three independent roots; units remain separate.", "",
                "| Profile | Object | JSON B | Compact B | Paired size ratio |", "|---|---|---:|---:|---:|"]
    for profile, summary in report["summary"].items():
        for name, value in summary["object_sizes_bytes"].items():
            row = [profile, name, value["json"]["median"], value["compact"]["median"],
                   value["paired_json_over_compact_ratio"]["median"]]
            wire.append(row)
            markdown.append(f"| {profile} | {name} | {row[2]:,} | {row[3]:,} | {row[4]:.3f} |")
        for mode, values in summary["modes"].items():
            memory.append([profile, mode, values["process_wall_seconds"]["median"],
                values["sampled_tree_peak_rss_bytes"]["median"]/2**20,
                values["sampled_tree_peak_rss_bytes"]["max"]/2**20,
                values["kernel_lifetime_peak_rss_bytes"]["median"]/2**20])
            for name, timing in values["phase_seconds_per_run_medians"].items():
                times.append([profile, mode, name, timing["count"], timing["min"], timing["median"], timing["max"]])
    markdown += ["", "| Profile | Setup s | Extract s | First sign s | Warm sign s | Warm verify s |",
                 "|---|---:|---:|---:|---:|---:|"]
    for profile, summary in report["summary"].items():
        values = summary["modes"]["generate"]["phase_seconds_per_run_medians"]
        markdown.append("| "+profile+" | "+" | ".join(f"{values[k]['median']:.6f}" for k in
            ("setup", "extract", "sign-first", "sign-warm", "verify-warm"))+" |")
    markdown += ["", "| Profile | Mode | Whole process s | Tree RSS median MiB | Tree RSS max MiB | Self kernel peak median MiB |",
                 "|---|---|---:|---:|---:|---:|"]
    markdown += ["| "+" | ".join(str(x) if isinstance(x, str) else f"{x:.6f}" for x in row)+" |" for row in memory]
    return {"wire.csv": csv_text(["profile", "object", "json_bytes_median", "compact_bytes_median", "paired_ratio_median"], wire),
            "timings.csv": csv_text(["profile", "mode", "phase", "independent_roots", "min_seconds", "median_seconds", "max_seconds"], times),
            "memory.csv": csv_text(["profile", "mode", "process_wall_seconds_median", "tree_peak_rss_MiB_median",
                                    "tree_peak_rss_MiB_max", "self_kernel_peak_rss_MiB_median"], memory),
            "tables.md": "\n".join(markdown)+"\n"}


if __name__ == "__main__":
    for name, text in render(json.loads((HERE/"benchmark.json").read_text())).items():
        (HERE/name).write_text(text, encoding="utf-8", newline="\n")
