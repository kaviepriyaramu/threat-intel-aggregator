"""
Threat Intelligence Aggregator - Feed Parser
Reads raw feed files in CSV, JSON, TXT, or simplified STIX bundle format and
extracts raw indicator strings + whatever metadata the format offers. Type
detection and validation happen later in normalizer.py - this module's job
is purely "get the indicators out of whatever format they arrived in".
"""

import csv
import json
import os
import re


def parse_csv(path):
    """CSV feeds: looks for a column that plausibly holds the indicator
    (ip, url, domain, hash, email) and yields (raw_value, row_metadata)."""
    indicator_cols = ("ip", "url", "domain", "hash", "email", "indicator")
    results = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            col = next((c for c in row if c.strip().lower() in indicator_cols), None)
            if not col or not row[col]:
                continue
            value = row[col].strip()
            meta = {k: v for k, v in row.items() if k != col}
            results.append((value, meta))
    return results


def parse_txt(path):
    """Plain text feeds: one indicator per line. Lines starting with # are
    comments and blank lines are skipped."""
    results = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            results.append((line, {}))
    return results


def parse_json(path):
    """JSON feeds: two shapes supported -
    1. A commercial-style feed: {"indicators": [{"url": "...", ...}, ...]}
    2. A simplified STIX bundle: {"type": "bundle", "objects": [...]}
    """
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict) and data.get("type") == "bundle":
        return _parse_stix_bundle(data)

    results = []
    indicators = data.get("indicators", []) if isinstance(data, dict) else data
    for item in indicators:
        if not isinstance(item, dict):
            continue
        value_key = next((k for k in ("url", "ip", "domain", "hash", "email", "value") if k in item), None)
        if not value_key:
            continue
        value = str(item[value_key]).strip()
        meta = {k: v for k, v in item.items() if k != value_key}
        results.append((value, meta))
    return results


_STIX_PATTERN_RE = re.compile(
    r"\[(?P<obj>[\w\-]+):(?P<prop>[\w.]+)\s*=\s*'(?P<value>[^']+)'\]"
)


def _parse_stix_bundle(data):
    """Extract the indicator value out of a STIX 'pattern' string like:
    [ipv4-addr:value = '1.2.3.4']  or  [file:hashes.MD5 = '...']"""
    results = []
    for obj in data.get("objects", []):
        if obj.get("type") != "indicator":
            continue
        pattern = obj.get("pattern", "")
        m = _STIX_PATTERN_RE.search(pattern)
        if not m:
            continue
        value = m.group("value")
        meta = {
            "stix_object_type": m.group("obj"),
            "stix_property": m.group("prop"),
            "labels": ",".join(obj.get("labels", [])),
            "valid_from": obj.get("valid_from", ""),
        }
        results.append((value, meta))
    return results


PARSERS = {
    ".csv": parse_csv,
    ".txt": parse_txt,
    ".json": parse_json,
}


def parse_feed(path):
    """Dispatch to the right parser based on file extension.
    Returns a list of (raw_value, metadata_dict) tuples."""
    ext = os.path.splitext(path)[1].lower()
    parser = PARSERS.get(ext)
    if not parser:
        raise ValueError(f"Unsupported feed format: {ext} ({path})")
    return parser(path)


def parse_all_feeds(feed_dir):
    """Parse every supported file in a directory. Returns a dict of
    {filename: [(raw_value, metadata), ...]}."""
    results = {}
    for fname in sorted(os.listdir(feed_dir)):
        ext = os.path.splitext(fname)[1].lower()
        if ext not in PARSERS:
            continue
        path = os.path.join(feed_dir, fname)
        results[fname] = parse_feed(path)
    return results
