"""
Threat Intelligence Aggregator - Normalization Engine
Takes raw (value, metadata) pairs from parser.py and converts them into a
single unified IOC schema, detecting the indicator type, validating it, and
discarding anything malformed or clearly not usable (e.g. private/reserved
IP ranges, which are never legitimate threat indicators to blocklist).

Unified schema (one dict per IOC):
    {
        "value": str,        # normalized indicator value
        "type": str,         # ip | domain | url | md5 | sha1 | sha256 | email
        "source": str,       # feed filename this occurrence came from
        "raw_metadata": dict,
        "seen_at": str,      # best-effort timestamp from the feed, or "" if none
    }
"""

import ipaddress
import re
from datetime import datetime, timezone

_URL_RE = re.compile(r"^https?://", re.I)
_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
_HEX_RE = re.compile(r"^[a-fA-F0-9]+$")

TIMESTAMP_KEYS = ("first_seen", "detected_on", "valid_from", "timestamp", "seen")


def detect_type(value: str):
    """Return the IOC type for a raw string, or None if it doesn't look
    like a valid indicator of any known type."""
    value = value.strip()

    if _URL_RE.match(value):
        return "url"

    if _HEX_RE.match(value) and len(value) in _HASH_LENGTHS:
        return _HASH_LENGTHS[len(value)]

    if _EMAIL_RE.match(value):
        return "email"

    try:
        ip = ipaddress.ip_address(value)
        if ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_link_local:
            return None  # not a usable threat indicator
        return "ip"
    except ValueError:
        pass

    if _DOMAIN_RE.match(value):
        tld = value.rsplit(".", 1)[-1]
        if tld.isdigit():
            return None  # looks like a malformed IP (e.g. 256.100.50.1), not a domain
        return "domain"

    return None


def _extract_timestamp(meta: dict) -> str:
    for key in TIMESTAMP_KEYS:
        if key in meta and meta[key]:
            return str(meta[key])
    return ""


def normalize_feed(source_name: str, raw_entries):
    """Convert a list of (raw_value, metadata) tuples into unified IOC dicts.
    Returns (normalized_list, rejected_list) - rejected entries are kept
    separately so the report can show what was filtered out and why."""
    normalized = []
    rejected = []
    seen_in_this_feed = set()

    for raw_value, meta in raw_entries:
        value = raw_value.strip()
        ioc_type = detect_type(value)

        if ioc_type is None:
            rejected.append({"value": value, "source": source_name, "reason": "invalid or non-routable"})
            continue

        # Normalize casing for domains/emails/urls (case-insensitive indicators)
        norm_value = value.lower() if ioc_type in ("domain", "email", "url") else value

        dedup_key = (ioc_type, norm_value)
        if dedup_key in seen_in_this_feed:
            continue  # duplicate within the same feed file
        seen_in_this_feed.add(dedup_key)

        normalized.append({
            "value": norm_value,
            "type": ioc_type,
            "source": source_name,
            "raw_metadata": meta,
            "seen_at": _extract_timestamp(meta),
        })

    return normalized, rejected


def normalize_all(parsed_feeds: dict):
    """parsed_feeds: {filename: [(raw_value, meta), ...]} from parser.parse_all_feeds().
    Returns (all_normalized, all_rejected) flattened across every feed."""
    all_normalized = []
    all_rejected = []
    for fname, entries in parsed_feeds.items():
        normalized, rejected = normalize_feed(fname, entries)
        all_normalized.extend(normalized)
        all_rejected.extend(rejected)
    return all_normalized, all_rejected
