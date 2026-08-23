"""
Threat Intelligence Aggregator - Correlation Engine
Groups normalized IOCs by (type, value) across every feed and scores them
by how many independent sources reported the same indicator. An indicator
seen in multiple feeds is far more likely to be a real, active threat than
one seen in a single low-confidence source - this is the core value-add of
aggregating feeds instead of using any single one in isolation.

Severity rule (kept simple and explainable, no ML involved):
    3+ independent sources -> HIGH
    2 independent sources  -> MEDIUM
    1 source               -> LOW
"""

from collections import defaultdict


def correlate(normalized_iocs):
    """Group IOCs by (type, value). Returns a list of correlated IOC records:
        {
            "type": str, "value": str,
            "sources": [source filenames, deduplicated],
            "source_count": int,
            "severity": "LOW" | "MEDIUM" | "HIGH",
            "occurrences": [the raw normalized dicts that contributed],
        }
    """
    groups = defaultdict(list)
    for ioc in normalized_iocs:
        groups[(ioc["type"], ioc["value"])].append(ioc)

    correlated = []
    for (ioc_type, value), occurrences in groups.items():
        sources = sorted({o["source"] for o in occurrences})
        count = len(sources)
        severity = "HIGH" if count >= 3 else "MEDIUM" if count == 2 else "LOW"
        correlated.append({
            "type": ioc_type,
            "value": value,
            "sources": sources,
            "source_count": count,
            "severity": severity,
            "occurrences": occurrences,
        })

    # Highest-risk first: more sources, then alphabetical for stable ordering
    correlated.sort(key=lambda r: (-r["source_count"], r["type"], r["value"]))
    return correlated


def summarize(correlated):
    """Quick counts used by the reporting module and CLI output."""
    by_type = defaultdict(int)
    by_severity = defaultdict(int)
    for r in correlated:
        by_type[r["type"]] += 1
        by_severity[r["severity"]] += 1
    return {
        "total_unique_indicators": len(correlated),
        "by_type": dict(by_type),
        "by_severity": dict(by_severity),
    }
