"""Generate standalone scientific figures/tables from verified public records."""
import argparse
import json
from pathlib import Path
import statistics

from .verify_backend_optimization import verify


def render(directory):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    checked = verify(directory)
    summary = checked["summary"]
    choices = (("A", "decrypt", "A / decrypt"), ("B", "encrypt", "B / encrypt"),
               ("Luo", "encrypt", "Luo / encrypt"), ("Luo", "decrypt", "Luo / decrypt"),
               ("Falcon", "decrypt", "Falcon / decrypt"))
    plt.rcParams.update({"font.family":"DejaVu Sans", "font.size":10, "axes.spines.top":False,
                         "axes.spines.right":False, "svg.fonttype":"none"})
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.7), gridspec_kw={"width_ratios":[1.3, 1]})
    for x, (label, operation, _) in enumerate(choices):
        data = json.loads((directory/(label+".json")).read_bytes())
        ratios = data["summary"][operation]["root_speedups"]
        axes[0].scatter([x-.11, x, x+.11], ratios, color="#147D92", s=36, zorder=3)
        median = summary[label][operation]["median_root_speedup"]
        axes[0].plot([x-.24, x+.24], [median]*2, color="#B5542A", linewidth=2.5, zorder=4)
    axes[0].axhline(1, color="#6F7680", linestyle="--", linewidth=1)
    axes[0].set_xticks(range(len(choices)), [item[2] for item in choices], rotation=20, ha="right")
    axes[0].set_ylabel("Warm full-protocol off / on time")
    axes[0].set_title("Paired ablations: 3 independent roots")
    axes[0].grid(axis="y", alpha=.2)
    c = summary["C"]
    ns = list(range(1, 11))
    axes[1].plot(ns, [n*c["original_decrypt_seconds"] for n in ns], marker="o", markersize=4,
                 color="#6B6F76", label="Original stateless decrypt")
    axes[1].plot(ns, [c["preparation_seconds"]+n*c["prepared_decrypt_seconds"] for n in ns],
                 marker="s", markersize=4, color="#147D92", label="Prepare once + session decrypt")
    axes[1].set_xlabel("Number of decryptions, fixed receiver / sender")
    axes[1].set_ylabel("Cumulative seconds (median extrapolation)")
    axes[1].set_title("C: one-root amortization, initial cost included")
    axes[1].grid(alpha=.2)
    axes[1].legend(frameon=False, fontsize=9)
    fig.suptitle("Preparation reuse with unchanged parameters and protocol checks", x=.03, ha="left", fontsize=13)
    fig.text(.03, .015, "Dots: root ratios; orange: median root ratio. C curve uses 2 stateless + 3 prepared observations; no cross-security ranking.", fontsize=8, color="#454A51")
    fig.tight_layout(rect=(.01,.055,.99,.93))
    for extension in ("svg", "pdf", "png"):
        fig.savefig(directory/("optimization."+extension), dpi=180, bbox_inches="tight")
    plt.close(fig)
    lines = ["# 同参数完整流程对照", "", "时间为三根各自根内中位数再取中位数；收益比为逐根off/on比值的中位数，两者相除不一定相等。", "",
             "| 组 | 操作 | 关闭／s | 开启／s | 根内收益比中位数 | 三根收益比范围 |",
             "|---|---|---:|---:|---:|---:|"]
    for label in ("A", "B", "Luo", "Falcon"):
        for name in ("encrypt", "decrypt"):
            value = summary[label][name]
            lines.append(f"| {label} | {name} | {value['off_seconds']:.6f} | {value['on_seconds']:.6f} | {value['median_root_speedup']:.3f} | {value['root_speedup_min']:.3f}–{value['root_speedup_max']:.3f} |")
    lines += ["", "A／Falcon加密与B解密是未针对其计算路径优化的对照；其变化不能当作相应优化的收益。", "",
              "## C：单根显式会话摊销", "", "| 项目 | 数值 |", "|---|---:|",
              f"| 原无状态解密中位数（2次）／s | {c['original_decrypt_seconds']:.6f} |",
              f"| 一次准备（包括真实Derive）／s | {c['preparation_seconds']:.6f} |",
              f"| 会话解密中位数（3次）／s | {c['prepared_decrypt_seconds']:.6f} |",
              f"| 额外叶钥编码／B | {c['leaf_key_bytes']} |", "",
              "| 连续解密次数 | 含一次准备的每条平均成本／s |", "|---:|---:|"]
    lines += [f"| {n} | {seconds:.6f} |" for n,seconds in c["amortized_seconds"].items()]
    lines += ["", "摊销公式为`(prepare + N * prepared_decrypt_median) / N`，N=10/100是同根中位数外推，未实际执行10/100次；不包含双方共同的Setup／发钥成本。C仅一根，不能外推为目标参数的重复基准。", ""]
    lines += ["## 准备与状态成本", "",
              "| 组 | 独立准备测量／s | 实际保留状态 | 签名钥编码／B | 接收者根钥编码／B | 计时阶段最高采样RSS／MiB |",
              "|---|---|---|---:|---:|---:|"]
    for label in ("A", "B", "C", "Luo", "Falcon"):
        batch = json.loads((directory/(label+".json")).read_bytes())
        records = batch["records"]
        peak = max(row["sampled_process_tree_peak_rss_bytes"] for record in records for row in record["phases"])
        sk = int(statistics.median(record["serialized_private_sizes"]["sender.bin"] for record in records))
        rk = int(statistics.median(record["serialized_private_sizes"]["receiver.bin"] for record in records))
        if label == "C":
            preparation, state = f"{c['preparation_seconds']:.3f}", f"额外叶钥编码 {c['leaf_key_bytes']} B，单身份对"
        elif label == "B":
            seconds = [row["seconds"] for record in records for row in record["phases"] if row["name"] == "signing-preparation"]
            preparation, state = f"{statistics.median(seconds):.3f}", "每根1条秘密准备计划，默认容量2"
        elif label == "Luo":
            preparation, state = "含于环构造，未隔离单测", "公开因子510整数＋置换256整数＋逆元1整数"
        else:
            preparation, state = "随首次验签，未隔离单测", "每根1条公开证书语句，默认容量64"
        lines.append(f"| {label} | {preparation} | {state} | {sk} | {rk} | {peak/2**20:.2f} |")
    lines += ["", "编码量是实际对象字节数（跨根取中位数），不是Python堆大小。RSS是同一进程中所有计时阶段的最大采样值，包含运行库、协议对象和两臂状态；不等于单独缓存大小，也不用于声称开启后节省内存。NTT关闭控制仍构造相同公开环，只切换蝶形执行路径，因此不是旧发行版全部准备成本的消除。", ""]
    if "supplemental_Luo_replay" in checked:
        lines += ["## Luo：控制随机重试的补充对照", "",
                  "复用原三根，每根3对；每对取一个新CSPRNG种子，使用明确TEST-ONLY的分域随机流在两臂重放。两臂完整密文与熵消费逐字节相等，9对均诚实解密成功；同一对是同一消息和OTS的重放，不计作两条独立新消息，不新增独立根。该对照不替换上面的新随机主批。", "",
                  "| 操作 | 关闭根中位数／s | 开启根中位数／s | 逐根收益比中位数 | 逐根范围 |", "|---|---:|---:|---:|---:|"]
        for name,value in checked["supplemental_Luo_replay"].items():
            lines.append(f"| {name} | {statistics.median(value['root_off_medians']):.6f} | {statistics.median(value['root_on_medians']):.6f} | {value['median_root_speedup']:.3f} | {min(value['root_speedups']):.3f}–{max(value['root_speedups']):.3f} |")
        lines += ["", "主批Luo加密没有显示稳定端到端收益；相同随机流对照下NTT路径只有小幅改善。报告应同时引用两批，不挑选有利样本，也不能把该控制试验当成新的生产随机独立基准。", ""]
    (directory/"tables.md").write_text("\n".join(lines), encoding="utf-8")
    (directory/"verified-summary.json").write_text(json.dumps(checked, indent=2, sort_keys=True)+"\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    render(parser.parse_args().directory)


if __name__ == "__main__":
    main()
