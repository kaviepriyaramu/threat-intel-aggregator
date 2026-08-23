"""
Threat Intelligence Aggregator - Reporting Module
Builds the final text summary: feeds processed, indicator counts by type,
high-priority repeated indicators, and rejected/invalid entries. Used both
for CLI/log output and as the data source for the practical report document.
"""

from datetime import datetime, timezone


def build_report(parsed_feeds, all_normalized, rejected, correlated, summary, blocklist_files):
    lines = []
    lines.append("=" * 64)
    lines.append("THREAT INTELLIGENCE AGGREGATOR - SUMMARY REPORT")
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
    lines.append("=" * 64)

    lines.append(f"\nFeeds processed: {len(parsed_feeds)}")
    for fname, entries in parsed_feeds.items():
        lines.append(f"   - {fname}: {len(entries)} raw entries")

    lines.append(f"\nTotal raw indicators parsed : {sum(len(v) for v in parsed_feeds.values())}")
    lines.append(f"Rejected (invalid/non-routable) : {len(rejected)}")
    lines.append(f"Total unique indicators after correlation : {summary['total_unique_indicators']}")

    lines.append("\nBy type:")
    for t, c in sorted(summary["by_type"].items(), key=lambda x: -x[1]):
        lines.append(f"   {t:8s} : {c}")

    lines.append("\nBy severity (source overlap):")
    for sev in ("HIGH", "MEDIUM", "LOW"):
        lines.append(f"   {sev:8s} : {summary['by_severity'].get(sev, 0)}")

    lines.append("\nHigh-priority indicators (seen in 2+ independent feeds):")
    high_priority = [r for r in correlated if r["source_count"] >= 2]
    if not high_priority:
        lines.append("   (none)")
    for r in high_priority:
        lines.append(f"   [{r['severity']:6s}] {r['type']:6s} {r['value']:45s} <- {', '.join(r['sources'])}")

    lines.append("\nRejected entries (sample, first 10):")
    for rej in rejected[:10]:
        lines.append(f"   {rej['value']!r} from {rej['source']} - {rej['reason']}")

    lines.append("\nBlocklist files generated:")
    for name, path in blocklist_files.items():
        lines.append(f"   {name}: {path}")

    lines.append("=" * 64)
    return "\n".join(lines)
