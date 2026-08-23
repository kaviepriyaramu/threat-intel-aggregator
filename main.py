"""
Threat Intelligence Aggregator (Non-AI) - Main Pipeline
Runs the full workflow: load feeds -> parse -> normalize & validate ->
correlate across sources -> generate blocklists -> produce a summary report.

Usage:
    python main.py [--feeds-dir feeds] [--output-dir output] [--min-severity MEDIUM]
"""

import argparse
import os

import parser as feed_parser  # local module, shadows nothing at runtime
import normalizer
import correlator
import blocklist_generator
import report


def run_pipeline(feeds_dir="feeds", output_dir="output", min_severity="MEDIUM"):
    print(f"[1/5] Loading feeds from '{feeds_dir}'...")
    parsed_feeds = feed_parser.parse_all_feeds(feeds_dir)
    for fname, entries in parsed_feeds.items():
        print(f"      {fname}: {len(entries)} raw entries")

    print("[2/5] Normalizing and validating indicators...")
    all_normalized, rejected = normalizer.normalize_all(parsed_feeds)
    print(f"      {len(all_normalized)} valid, {len(rejected)} rejected")

    print("[3/5] Correlating indicators across feeds...")
    correlated = correlator.correlate(all_normalized)
    summary = correlator.summarize(correlated)
    print(f"      {summary['total_unique_indicators']} unique indicators "
          f"({summary['by_severity'].get('HIGH', 0)} HIGH, "
          f"{summary['by_severity'].get('MEDIUM', 0)} MEDIUM, "
          f"{summary['by_severity'].get('LOW', 0)} LOW)")

    print(f"[4/5] Generating blocklists (min severity: {min_severity})...")
    blocklist_files = blocklist_generator.generate_blocklists(correlated, output_dir, min_severity)
    for name, path in blocklist_files.items():
        print(f"      {name}: {path}")

    print("[5/5] Building summary report...")
    report_text = report.build_report(parsed_feeds, all_normalized, rejected, correlated, summary, blocklist_files)
    report_path = os.path.join(output_dir, "ti_summary_report.txt")
    with open(report_path, "w") as f:
        f.write(report_text)
    print(f"      Report written to {report_path}\n")

    print(report_text)
    return dict(parsed_feeds=parsed_feeds, normalized=all_normalized, rejected=rejected,
                correlated=correlated, summary=summary, blocklist_files=blocklist_files)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Threat Intelligence Aggregator (Non-AI)")
    ap.add_argument("--feeds-dir", default="feeds")
    ap.add_argument("--output-dir", default="output")
    ap.add_argument("--min-severity", default="MEDIUM", choices=["LOW", "MEDIUM", "HIGH"])
    args = ap.parse_args()

    run_pipeline(args.feeds_dir, args.output_dir, args.min_severity)
