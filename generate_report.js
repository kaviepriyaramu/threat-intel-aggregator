const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, Table, TableRow, TableCell,
  WidthType, ShadingType, ImageRun, AlignmentType, PageBreak
} = require("docx");

const PAGE = { size: { width: 12240, height: 15840 } };

function h1(text) { return new Paragraph({ text, heading: HeadingLevel.HEADING_1, spacing: { before: 300, after: 150 } }); }
function h2(text) { return new Paragraph({ text, heading: HeadingLevel.HEADING_2, spacing: { before: 250, after: 120 } }); }
function p(text) { return new Paragraph({ children: [new TextRun({ text })], spacing: { after: 120 } }); }
function bullet(text) { return new Paragraph({ text, bullet: { level: 0 }, spacing: { after: 60 } }); }
function mono(text) { return new Paragraph({ children: [new TextRun({ text, font: "Consolas", size: 18 })], spacing: { after: 40 } }); }

function cell(text, opts = {}) {
  return new TableCell({
    width: { size: opts.width || 2000, type: WidthType.DXA },
    shading: opts.header ? { type: ShadingType.CLEAR, fill: "E1F5EE" } : undefined,
    children: [new Paragraph({ children: [new TextRun({ text, bold: !!opts.header, size: 19 })] })],
  });
}

function image(path, width, height) {
  return new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { after: 200 },
    children: [new ImageRun({ type: "png", data: fs.readFileSync(path), transformation: { width, height } })],
  });
}

// ---------------- Real data from the pipeline run ----------------
const feedsProcessed = 6;
const rawIndicators = 37;
const rejected = 2;
const uniqueIndicators = 24;
const byType = [
  ["ip", 7], ["url", 6], ["domain", 5], ["md5", 2], ["email", 2], ["sha1", 1], ["sha256", 1],
];
const bySeverity = [["HIGH", 1], ["MEDIUM", 6], ["LOW", 17]];
const highPriority = [
  ["HIGH", "ip", "185.220.101.45", "feed_osint_ips.csv, feed_osint_mixed.txt, feed_stix_sample.json"],
  ["MEDIUM", "domain", "malware-drop-zone.xyz", "feed_cert_domains.txt, feed_stix_sample.json"],
  ["MEDIUM", "domain", "secure-bank-verification.info", "feed_cert_domains.txt, feed_osint_mixed.txt"],
  ["MEDIUM", "domain", "update-secure-check.com", "feed_cert_domains.txt, feed_osint_mixed.txt"],
  ["MEDIUM", "ip", "194.147.78.23", "feed_osint_ips.csv, feed_osint_mixed.txt"],
  ["MEDIUM", "ip", "91.219.237.244", "feed_osint_ips.csv, feed_osint_mixed.txt"],
  ["MEDIUM", "md5", "5d41402abc4b2a76b9719d911017c592", "feed_siem_hashes.csv, feed_stix_sample.json"],
];

const doc = new Document({
  sections: [{
    properties: { page: PAGE },
    children: [
      // ---------------- Title Page ----------------
      new Paragraph({ text: "", spacing: { after: 1200 } }),
      new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "Threat Intelligence Aggregator", bold: true, size: 52 })], spacing: { after: 100 } }),
      new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "(Non-AI) - Multi-Feed IOC Correlation & Blocklist Toolkit", size: 26 })], spacing: { after: 60 } }),
      new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "Practical Work Documentation - Journal & Final Report", size: 24, italics: true })], spacing: { after: 800 } }),
      new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "Submitted by: Kaviepriya", size: 22 })] }),
      new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "Program: B.E./B.Tech Computer Science and Engineering", size: 22 })] }),
      new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "Domain: Threat Intelligence / Blue Team SOC Practical Training", size: 22 })] }),
      new Paragraph({ children: [new PageBreak()] }),

      // ---------------- 1. Overview ----------------
      h1("1. Project Overview"),
      p("This project is a Threat Intelligence (TI) Aggregator that collects Indicators of Compromise (IOCs) from multiple feeds in different formats (CSV, TXT, JSON, and simplified STIX bundles), normalizes them into a single schema, validates them, correlates repeated indicators across sources, and produces deployable blocklists for firewalls, web filters, and EDR/AV tools. No AI or machine learning is used - every decision (type detection, validation, severity scoring) is deterministic and explainable, which matters for a SOC tool whose output feeds directly into blocking rules."),
      p("The system was implemented in Python, covered by an automated test suite, and run end-to-end against six sample feeds with deliberately overlapping indicators, to demonstrate the core value of TI aggregation: an indicator reported by multiple independent sources is far more trustworthy than one reported by a single source."),

      h2("1.1 Objectives"),
      bullet("Collect and parse IOCs from multiple feed formats without relying on any single source."),
      bullet("Normalize heterogeneous indicators (IPs, domains, URLs, hashes, emails) into one unified schema."),
      bullet("Validate indicators and discard anything non-routable or malformed (e.g. private IP ranges)."),
      bullet("Correlate indicators across feeds and assign a severity rating based on source overlap."),
      bullet("Generate deployable blocklists in formats real security tools consume (plain-text IP/domain lists, CSV hash lists)."),
      bullet("Validate the parsing and correlation logic with automated unit tests rather than manual spot-checks alone."),

      // ---------------- 2. Architecture ----------------
      h1("2. System Architecture"),
      p("The diagram below shows the full pipeline implemented across parser.py, normalizer.py, correlator.py, blocklist_generator.py, and report.py, orchestrated by main.py."),
      image("architecture.png", 400, 412),
      p("Components:"),
      bullet("Feed parser (parser.py) - format-specific extraction for CSV, TXT, JSON, and a simplified STIX bundle format (regex-parsed STIX 'pattern' strings, e.g. [ipv4-addr:value = '1.2.3.4'])."),
      bullet("Normalization engine (normalizer.py) - detects indicator type (ip / domain / url / md5 / sha1 / sha256 / email) using the ipaddress module, regex, and hash-length checks; rejects private/reserved/loopback IPs and malformed values; deduplicates within each feed; lowercases case-insensitive indicator types."),
      bullet("Correlation engine (correlator.py) - groups indicators by (type, value) across every feed and counts independent sources. Severity: 3+ sources = HIGH, 2 sources = MEDIUM, 1 source = LOW."),
      bullet("Blocklist generator (blocklist_generator.py) - exports MEDIUM+ severity indicators into an IP blocklist (firewall), a web blocklist (domains + URLs), and a hash blocklist (EDR/AV), plus a full JSON dataset including LOW severity for archival."),
      bullet("Reporting module (report.py) - builds the text summary used both for CLI output and this report."),

      // ---------------- 3. Practical Journal ----------------
      new Paragraph({ children: [new PageBreak()] }),
      h1("3. Practical Journal"),

      h2("3.1 Purpose of the Experiment"),
      p("To build a working, non-AI TI aggregation pipeline, feed it realistic sample data with deliberate cross-feed overlaps, and verify that repeated indicators are correctly identified as higher-confidence threats than single-source ones - the central premise of TI aggregation."),

      h2("3.2 Tools Used"),
      bullet("Python 3.12 - all pipeline modules"),
      bullet("re, ipaddress, hashlib-equivalent length checks - indicator type detection and validation"),
      bullet("csv / json - feed parsing and blocklist export"),
      bullet("pytest - automated unit tests for the normalizer and correlator"),
      bullet("matplotlib - analysis charts for this report"),

      h2("3.3 Step-by-Step Execution"),
      bullet("Step 1: Designed the unified IOC schema (value, type, source, raw_metadata, seen_at) that every feed format normalizes into."),
      bullet("Step 2: Built the feed parser for CSV, TXT, and JSON (including a simplified STIX bundle parser using a regex against the STIX 'pattern' field)."),
      bullet("Step 3: Built the normalization engine with type detection for IPs, domains, URLs, MD5/SHA1/SHA256 hashes, and emails, including rejection of private/reserved IP ranges."),
      bullet("Step 4: Wrote 22 pytest unit tests against the normalizer and correlator before running the full pipeline."),
      bullet("Step 5: Ran the test suite - it failed 2 tests on the first run, catching two real bugs (Section 3.5)."),
      bullet("Step 6: Built 6 sample feeds (OSINT IPs, a commercial URL feed, a CERT domain advisory, an internal SIEM hash export, a STIX bundle, and a second mixed OSINT feed) with deliberate overlaps so correlation would have something real to find."),
      bullet("Step 7: Ran the full pipeline end-to-end and reviewed the generated blocklists and summary report against the raw feed data by hand to confirm the correlation counts were correct."),

      h2("3.4 Observations (Charts)"),
      p("Correlated indicators by severity (source overlap) - the single HIGH-severity indicator, an IP seen in three independent feeds, is exactly the kind of signal this system is designed to surface:"),
      image("analysis_chart.png", 380, 266),
      p("Unique indicators by type after correlation and deduplication:"),
      image("type_chart.png", 420, 252),

      h2("3.5 Interpretation of Results (Bugs Found and Fixed)"),
      p("Two real bugs surfaced while writing and running the test suite, before any manual testing:"),
      bullet("The domain-detection regex matched any dot-separated sequence of alphanumeric labels, including malformed IP addresses like 256.100.50.1 (an invalid IP, since 256 exceeds a valid octet). Since ipaddress.ip_address() correctly rejects it as an IP, the value fell through to the domain check and matched, because the regex has no concept of 'this looks like an IP that just happens to be invalid'. Fixed by rejecting any domain match whose final label (TLD) is purely numeric - real domain TLDs are never all-digits, so this is a safe, narrow fix rather than a broad regex rewrite."),
      bullet("The initial sample feed data used RFC 5737 'documentation range' IP addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) as stand-ins for fake malicious IPs. Python's ipaddress module correctly classifies these as non-routable (is_private returns True for them), so they were being rejected exactly as a real deployment should reject them - but that broke the demo data. This wasn't a code bug so much as a reminder that 'safe' example IP ranges and 'realistic-looking' IP ranges are not the same thing when the validation logic is actually doing its job; the sample feeds were updated to use ordinary public-looking IPs instead."),
      p("The correlation results confirm the system does what it's meant to: 185.220.101.45 was independently reported by an OSINT IP feed, a second mixed OSINT feed, and a STIX bundle - three unrelated sources - and was correctly scored HIGH and included in the firewall blocklist. Six other indicators reached MEDIUM by appearing in exactly two feeds. The other 17 unique indicators were single-source and correctly excluded from the deployable blocklists by default, while still being retained in the full JSON dataset for analyst review."),

      // ---------------- 4. Final Report ----------------
      new Paragraph({ children: [new PageBreak()] }),
      h1("4. Final Report"),

      h2("4.1 Feed & Indicator Summary"),
      bullet(`Feeds processed: ${feedsProcessed} (CSV x2, JSON x2, TXT x2)`),
      bullet(`Total raw indicators parsed: ${rawIndicators}`),
      bullet(`Rejected as invalid or non-routable: ${rejected}`),
      bullet(`Total unique indicators after correlation: ${uniqueIndicators}`),

      h2("4.2 Indicators by Type"),
      new Table({
        width: { size: 5000, type: WidthType.DXA },
        columnWidths: [2500, 2500],
        rows: [
          new TableRow({ children: [cell("Type", { header: true, width: 2500 }), cell("Count", { header: true, width: 2500 })] }),
          ...byType.map(([t, c]) => new TableRow({ children: [cell(t, { width: 2500 }), cell(String(c), { width: 2500 })] })),
        ],
      }),
      new Paragraph({ text: "", spacing: { after: 200 } }),

      h2("4.3 Indicators by Severity (Source Overlap)"),
      new Table({
        width: { size: 5000, type: WidthType.DXA },
        columnWidths: [2500, 2500],
        rows: [
          new TableRow({ children: [cell("Severity", { header: true, width: 2500 }), cell("Count", { header: true, width: 2500 })] }),
          ...bySeverity.map(([s, c]) => new TableRow({ children: [cell(s, { width: 2500 }), cell(String(c), { width: 2500 })] })),
        ],
      }),
      new Paragraph({ text: "", spacing: { after: 200 } }),

      h2("4.4 High-Priority Indicators (2+ Independent Sources)"),
      new Table({
        width: { size: 9500, type: WidthType.DXA },
        columnWidths: [1300, 1000, 2800, 4400],
        rows: [
          new TableRow({ children: [cell("Severity", { header: true, width: 1300 }), cell("Type", { header: true, width: 1000 }), cell("Value", { header: true, width: 2800 }), cell("Sources", { header: true, width: 4400 })] }),
          ...highPriority.map(([sev, type, val, src]) =>
            new TableRow({ children: [cell(sev, { width: 1300 }), cell(type, { width: 1000 }), cell(val, { width: 2800 }), cell(src, { width: 4400 })] })
          ),
        ],
      }),
      new Paragraph({ text: "", spacing: { after: 200 } }),

      h2("4.5 Blocklist Deliverables"),
      bullet("blocklist_ips.txt - 3 IPs (firewall / IP-set format), MEDIUM+ severity only"),
      bullet("blocklist_web.txt - 3 domains, 0 URLs (web filter format), MEDIUM+ severity only"),
      bullet("blocklist_hashes.csv - 1 hash with algorithm and severity columns (EDR/AV format), MEDIUM+ severity only"),
      bullet("blocklist_emails.txt - 0 entries at MEDIUM+ in this run (informational format for suspicious sender addresses)"),
      bullet("ioc_dataset_full.json - all 24 correlated indicators including LOW severity, for archival and analyst review"),

      h2("4.6 Validation"),
      bullet("Unit test suite: 22/22 tests passing (pytest tests/) after fixing the two bugs described in Section 3.5."),
      bullet("Manual cross-check: every HIGH and MEDIUM severity indicator in the correlation output was manually traced back to its source feed files to confirm the source count was correct."),
      bullet("False-positive check: 0 private/internal IPs (10.0.0.5) made it into any blocklist; the deliberately invalid IP (256.100.50.1) was correctly rejected rather than being misclassified as a domain."),

      h2("4.7 Observed Patterns"),
      bullet("The IP 185.220.101.45 appearing across an OSINT feed, a second independent OSINT feed, and a STIX bundle is a realistic pattern for actively-tracked infrastructure (e.g. a known Tor exit node or C2 host that multiple TI providers have independently observed) - exactly the case where cross-source correlation adds real confidence beyond what any single feed can offer."),
      bullet("Domains overlapping between the CERT advisory feed and the mixed OSINT feed (update-secure-check.com, secure-bank-verification.info) suggest an active phishing campaign being tracked by more than one source."),
      bullet("The majority of indicators (17 of 24) were single-source only - this is expected and realistic; most feeds report plenty of low-confidence, unconfirmed intelligence, which is exactly why a minimum-severity threshold on the deployable blocklists matters."),

      h2("4.8 Suggested Improvements"),
      bullet("Add a feed-reliability weighting so a match from a historically accurate source counts for more than a match from a noisy one, rather than treating all sources as equal."),
      bullet("Add IOC aging/expiry - an indicator not re-confirmed by any feed after N days should be demoted rather than staying at its peak severity forever."),
      bullet("Add native STIX/TAXII feed polling instead of static bundle files, for real feed ingestion rather than offline sample data."),
      bullet("Add IP range (CIDR) and domain-wildcard correlation, so related indicators from the same infrastructure block are grouped even when the exact values differ."),
      bullet("Integrate directly with firewall/EDR APIs to push blocklists automatically, rather than requiring a manual import step."),

      h2("4.9 Conclusion"),
      p("This project built a complete, explainable, non-AI TI aggregation pipeline: parsing four feed formats into one schema, validating indicators with concrete rules (not guesses), correlating across sources to separate confirmed threats from single-source noise, and exporting the result into formats real security tools can consume directly. Writing unit tests before running the full pipeline caught two genuine bugs - a validation edge case and a sample-data assumption - that would have been easy to miss testing by eye alone. The clearest takeaway is that the value of a TI aggregator isn't any single clever technique; it's the discipline of normalizing everything to one schema before comparing it, which is what makes cross-feed correlation possible at all."),
    ],
  }],
});

Packer.toBuffer(doc).then((buf) => {
  fs.writeFileSync("TI_Aggregator_Practical_Report.docx", buf);
  console.log("Report written.");
});
