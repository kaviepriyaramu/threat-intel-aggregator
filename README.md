# Threat Intelligence Aggregator (Non-AI)

A multi-feed IOC collection, normalization, correlation, and blocklist
generation toolkit. No AI/ML - every decision (type detection, validation,
severity scoring) is a deterministic, explainable rule, which matters for a
tool whose output can feed directly into firewall/EDR blocking rules.

## What's included

| File | Purpose |
|---|---|
| `main.py` | Orchestrates the full pipeline end to end |
| `parser.py` | Parses CSV, TXT, JSON, and simplified STIX bundle feeds |
| `normalizer.py` | Detects IOC type (ip/domain/url/md5/sha1/sha256/email), validates, deduplicates |
| `correlator.py` | Groups IOCs across feeds, scores severity by source overlap |
| `blocklist_generator.py` | Exports firewall/web/EDR blocklists + full JSON dataset |
| `report.py` | Builds the text summary report |
| `make_charts.py` | Generates the analysis charts used in the report |
| `feeds/` | 6 sample feeds (CSV, JSON, TXT, STIX) with deliberate cross-feed overlaps |
| `output/` | Generated blocklists + summary report (created on first run) |
| `tests/` | 22 pytest unit tests for the normalizer and correlator |
| `TI_Aggregator_Practical_Report.docx/.pdf` | Practical journal + final report with real results |
| `TI_Aggregator_Presentation.pptx` | 9-slide presentation deck |

## How it works

```
Raw feeds (CSV/TXT/JSON/STIX)
  -> Parser (format-specific extraction)
  -> Normalizer (type detection + validation; rejects private/malformed values)
  -> Correlator (cross-feed matching; severity by source count)
       3+ sources = HIGH, 2 sources = MEDIUM, 1 source = LOW
  -> Blocklist generator (MEDIUM+ only, by default)
  -> Reporting module (summary + high-priority indicators)
```

## How to run it yourself

```bash
# 1. Install dependencies
pip install matplotlib pytest --break-system-packages

# 2. Run the test suite (optional but recommended)
pytest tests/ -v

# 3. Run the full pipeline
python main.py
# Reads from feeds/, writes to output/

# 4. Regenerate the report charts (optional)
python make_charts.py
```

### Tuning the blocklist threshold

```bash
python main.py --min-severity HIGH   # only export HIGH-severity indicators
python main.py --min-severity LOW    # export everything, including single-source
```

### Adding your own feeds

Drop a `.csv`, `.txt`, or `.json` file into `feeds/` and re-run `main.py`.
- CSV: needs a column named `ip`, `url`, `domain`, `hash`, `email`, or `indicator`
- TXT: one indicator per line, `#` for comments
- JSON: either `{"indicators": [{"url": "...", ...}, ...]}` or a STIX bundle
  (`{"type": "bundle", "objects": [{"type": "indicator", "pattern": "[ipv4-addr:value = '1.2.3.4']", ...}]}`)

## Notes worth mentioning in a viva / interview

- **Two real bugs were caught by the unit tests**, not manual testing:
  1. A malformed IP like `256.100.50.1` was falling through to the domain
     regex and matching, since the regex had no concept of "this is an
     invalid IP, not a domain." Fixed by rejecting any domain match whose
     final label (TLD) is purely numeric.
  2. The original sample feed data used RFC 5737 "documentation range" IPs
     (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) as fake malicious
     IPs. Python's `ipaddress` module correctly flags these as non-routable
     (`is_private` is True for them), so they were being rejected exactly as
     a real deployment should - the fix was updating the sample data, not
     the validation logic, since the validation was right.
- **Severity is source overlap, not payload analysis** - this project
  doesn't try to judge how "bad" an indicator looks, only how many
  independent sources agree it's worth watching. That's a deliberate,
  explainable design choice suited to a non-AI system.
- **MEDIUM+ threshold on blocklists is a deliberate design choice** - a
  single-source LOW-confidence indicator is kept in the full JSON dataset
  for analyst visibility, but isn't pushed straight into a deployable
  blocklist without corroboration from a second source.
