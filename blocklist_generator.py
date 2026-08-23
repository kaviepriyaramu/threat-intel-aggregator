"""
Threat Intelligence Aggregator - Blocklist Generator
Takes correlated IOCs and exports them into the formats different security
tools actually consume:
    - Firewalls / IP sets: plain-text list of IPs, one per line
    - Web filters: plain-text list of malicious domains + full URLs
    - EDR/AV: CSV of hashes with algorithm, ready for hash-based blocking
    - Full dataset: a single JSON export of everything, for archival / re-import

Only IOCs at or above a minimum severity are included in the deployable
blocklists by default (MEDIUM+) - a single-source LOW-confidence indicator
is kept in the full JSON export for visibility, but isn't pushed straight
to a firewall rule without a human looking at it first, which mirrors how
most real SOC workflows treat single-source intel.
"""

import csv
import json
import os

MIN_SEVERITY_FOR_BLOCKLIST = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
DEFAULT_MIN_SEVERITY = "MEDIUM"


def _meets_threshold(severity, min_severity):
    return MIN_SEVERITY_FOR_BLOCKLIST[severity] >= MIN_SEVERITY_FOR_BLOCKLIST[min_severity]


def generate_blocklists(correlated, output_dir, min_severity=DEFAULT_MIN_SEVERITY):
    os.makedirs(output_dir, exist_ok=True)
    written = {}

    eligible = [r for r in correlated if _meets_threshold(r["severity"], min_severity)]

    # --- Firewall IP blocklist ---
    ip_path = os.path.join(output_dir, "blocklist_ips.txt")
    ips = sorted({r["value"] for r in eligible if r["type"] == "ip"})
    with open(ip_path, "w") as f:
        f.write("# SentinelTI - Firewall IP blocklist\n")
        f.write(f"# {len(ips)} indicators, severity >= {min_severity}\n")
        for ip in ips:
            f.write(ip + "\n")
    written["ip_blocklist"] = ip_path

    # --- Web filter: domains + URLs ---
    web_path = os.path.join(output_dir, "blocklist_web.txt")
    domains = sorted({r["value"] for r in eligible if r["type"] == "domain"})
    urls = sorted({r["value"] for r in eligible if r["type"] == "url"})
    with open(web_path, "w") as f:
        f.write("# SentinelTI - Web filter blocklist (domains + URLs)\n")
        f.write(f"# {len(domains)} domains, {len(urls)} URLs, severity >= {min_severity}\n")
        for d in domains:
            f.write(d + "\n")
        for u in urls:
            f.write(u + "\n")
    written["web_blocklist"] = web_path

    # --- EDR/AV hash blocklist ---
    hash_path = os.path.join(output_dir, "blocklist_hashes.csv")
    hash_rows = sorted(
        [r for r in eligible if r["type"] in ("md5", "sha1", "sha256")],
        key=lambda r: (r["type"], r["value"]),
    )
    with open(hash_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["hash", "algorithm", "source_count", "severity"])
        for r in hash_rows:
            writer.writerow([r["value"], r["type"], r["source_count"], r["severity"]])
    written["hash_blocklist"] = hash_path

    # --- Emails (informational - not typically "blocklisted" the same way) ---
    email_path = os.path.join(output_dir, "blocklist_emails.txt")
    emails = sorted({r["value"] for r in eligible if r["type"] == "email"})
    with open(email_path, "w") as f:
        f.write("# SentinelTI - Suspicious sender / contact email addresses\n")
        for e in emails:
            f.write(e + "\n")
    written["email_blocklist"] = email_path

    # --- Full dataset export (everything, including LOW severity, as JSON) ---
    json_path = os.path.join(output_dir, "ioc_dataset_full.json")
    export = [
        {
            "type": r["type"],
            "value": r["value"],
            "severity": r["severity"],
            "source_count": r["source_count"],
            "sources": r["sources"],
        }
        for r in correlated
    ]
    with open(json_path, "w") as f:
        json.dump(export, f, indent=2)
    written["full_dataset"] = json_path

    return written
