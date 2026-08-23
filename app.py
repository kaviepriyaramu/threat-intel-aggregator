"""
Threat Intelligence Aggregator - Web Dashboard
A thin Flask wrapper around the CLI pipeline (main.py) so the aggregator's
results are viewable in a browser and deployable as a web service.
"""

import os
from flask import Flask, render_template, jsonify, send_from_directory, redirect, url_for

import parser as feed_parser
import normalizer
import correlator
import blocklist_generator
import report

app = Flask(__name__)

FEEDS_DIR = os.path.join(os.path.dirname(__file__), "feeds")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")

_cache = {}


def run_pipeline():
    parsed_feeds = feed_parser.parse_all_feeds(FEEDS_DIR)
    all_normalized, rejected = normalizer.normalize_all(parsed_feeds)
    correlated = correlator.correlate(all_normalized)
    summary = correlator.summarize(correlated)
    blocklist_files = blocklist_generator.generate_blocklists(correlated, OUTPUT_DIR)
    report_text = report.build_report(parsed_feeds, all_normalized, rejected, correlated, summary, blocklist_files)
    with open(os.path.join(OUTPUT_DIR, "ti_summary_report.txt"), "w") as f:
        f.write(report_text)

    _cache.update(dict(
        parsed_feeds=parsed_feeds, normalized=all_normalized, rejected=rejected,
        correlated=correlated, summary=summary, blocklist_files=blocklist_files,
        report_text=report_text,
    ))
    return _cache


@app.route("/")
def home():
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
def dashboard():
    data = run_pipeline()
    correlated = data["correlated"]
    high_priority = [r for r in correlated if r["source_count"] >= 2]

    return render_template(
        "dashboard.html",
        feeds_processed=len(data["parsed_feeds"]),
        feed_names=list(data["parsed_feeds"].keys()),
        raw_count=sum(len(v) for v in data["parsed_feeds"].values()),
        rejected_count=len(data["rejected"]),
        summary=data["summary"],
        high_priority=high_priority,
        all_correlated=sorted(correlated, key=lambda r: (-r["source_count"], r["type"])),
        blocklist_files={k: os.path.basename(v) for k, v in data["blocklist_files"].items()},
    )


@app.route("/api/summary")
def api_summary():
    data = run_pipeline()
    return jsonify({
        "feeds_processed": len(data["parsed_feeds"]),
        "raw_indicators": sum(len(v) for v in data["parsed_feeds"].values()),
        "rejected": len(data["rejected"]),
        "unique_indicators": data["summary"]["total_unique_indicators"],
        "by_type": data["summary"]["by_type"],
        "by_severity": data["summary"]["by_severity"],
        "high_priority": [
            {"type": r["type"], "value": r["value"], "severity": r["severity"],
             "source_count": r["source_count"], "sources": r["sources"]}
            for r in data["correlated"] if r["source_count"] >= 2
        ],
    })


@app.route("/download/<path:filename>")
def download(filename):
    return send_from_directory(OUTPUT_DIR, filename, as_attachment=True)


@app.route("/rerun")
def rerun():
    run_pipeline()
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(debug=False, port=5000)
