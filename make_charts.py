"""
Generates analysis_chart.png (severity breakdown) and type_chart.png
(indicator type breakdown) from a fresh pipeline run, for use in the report.
"""

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import parser as feed_parser
import normalizer
import correlator


def main():
    parsed_feeds = feed_parser.parse_all_feeds("feeds")
    all_normalized, rejected = normalizer.normalize_all(parsed_feeds)
    correlated = correlator.correlate(all_normalized)
    summary = correlator.summarize(correlated)

    # --- Severity breakdown ---
    sev_order = ["HIGH", "MEDIUM", "LOW"]
    sev_counts = [summary["by_severity"].get(s, 0) for s in sev_order]
    colors = ["#e63946", "#f4a261", "#a8a29e"]

    plt.figure(figsize=(6, 4.2))
    bars = plt.bar(sev_order, sev_counts, color=colors)
    plt.title("Correlated Indicators by Severity (Source Overlap)")
    plt.ylabel("Number of Indicators")
    for b, c in zip(bars, sev_counts):
        plt.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.2, str(c), ha="center", va="bottom", fontsize=10)
    plt.tight_layout()
    plt.savefig("analysis_chart.png", dpi=150)
    plt.close()

    # --- Type breakdown ---
    types = sorted(summary["by_type"].keys(), key=lambda t: -summary["by_type"][t])
    counts = [summary["by_type"][t] for t in types]

    plt.figure(figsize=(7, 4.2))
    bars = plt.bar(types, counts, color="#5DCAA5")
    plt.title("Unique Indicators by Type (After Correlation)")
    plt.ylabel("Number of Indicators")
    plt.xlabel("Indicator Type")
    for b, c in zip(bars, counts):
        plt.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.2, str(c), ha="center", va="bottom", fontsize=10)
    plt.tight_layout()
    plt.savefig("type_chart.png", dpi=150)
    plt.close()

    print("Charts saved: analysis_chart.png, type_chart.png")


if __name__ == "__main__":
    main()
