const pptxgen = require("pptxgenjs");

const NAVY = "13203D";
const NAVY2 = "1C2C52";
const AMBER = "F2A65A";
const RED = "E24B4A";
const TEAL = "5DCAA5";
const CREAM = "F4F1EA";
const MUTED = "9AA3B8";

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE"; // 13.3 x 7.5

function titleBar(slide, kicker, title) {
  slide.addText(kicker.toUpperCase(), { x: 0.6, y: 0.35, w: 8, h: 0.35, fontSize: 12, color: AMBER, bold: true, charSpacing: 2 });
  slide.addText(title, { x: 0.6, y: 0.65, w: 11.5, h: 0.7, fontSize: 26, color: "FFFFFF", bold: true });
}

// ---------------- Slide 1: Title ----------------
{
  const s = pres.addSlide();
  s.background = { color: NAVY };
  s.addShape("rect", { x: 0, y: 0, w: 0.18, h: 7.5, fill: { color: AMBER } });
  s.addText("THREAT INTELLIGENCE AGGREGATOR", { x: 0.9, y: 2.5, w: 11.5, h: 1.2, fontSize: 40, bold: true, color: "FFFFFF" });
  s.addText("A non-AI, multi-feed IOC correlation and blocklist toolkit", { x: 0.9, y: 3.55, w: 11, h: 0.6, fontSize: 18, color: MUTED });
  s.addText("Kaviepriya  |  B.E./B.Tech CSE  |  Threat Intelligence / Blue Team SOC Practical", { x: 0.9, y: 6.6, w: 11, h: 0.4, fontSize: 13, color: MUTED });
}

// ---------------- Slide 2: Motivation ----------------
{
  const s = pres.addSlide();
  s.background = { color: CREAM };
  titleBar2(s, "Why this project", "One feed alone isn't enough");
  const points = [
    ["Feeds are scattered", "OSINT, commercial TI, internal SIEM/EDR logs, and CERT advisories all report indicators in different formats and structures."],
    ["Single-source noise", "Any one feed reports plenty of low-confidence, unconfirmed intel - trusting it alone means false positives or missed threats."],
    ["Correlation is the value", "An indicator seen across multiple independent sources is far more likely to be a real, active threat."],
  ];
  let x = 0.6;
  points.forEach(([h, body]) => {
    s.addShape("roundRect", { x, y: 1.7, w: 3.9, h: 4.6, rectRadius: 0.12, fill: { color: "FFFFFF" }, line: { color: "D8D4C8", width: 1 } });
    s.addShape("rect", { x: x + 0.35, y: 2.05, w: 0.55, h: 0.08, fill: { color: AMBER } });
    s.addText(h, { x: x + 0.35, y: 2.25, w: 3.2, h: 0.7, fontSize: 17, bold: true, color: NAVY });
    s.addText(body, { x: x + 0.35, y: 2.95, w: 3.2, h: 3.1, fontSize: 13, color: "4A4A46" });
    x += 4.15;
  });
}

// ---------------- Slide 3: Objectives ----------------
{
  const s = pres.addSlide();
  s.background = { color: NAVY };
  titleBar(s, "Scope", "Project objectives");
  const objs = [
    "Collect & parse IOCs from CSV, TXT, JSON, and STIX feeds",
    "Normalize heterogeneous indicators into one unified schema",
    "Validate indicators - reject private/reserved/malformed values",
    "Correlate across feeds; score severity by source overlap",
    "Generate deployable blocklists (firewall / web filter / EDR)",
    "Validate logic with automated unit tests, not manual spot-checks",
  ];
  objs.forEach((t, i) => {
    const col = i % 2, row = Math.floor(i / 2);
    const x = 0.7 + col * 6.1, y = 1.9 + row * 1.55;
    s.addShape("roundRect", { x, y, w: 5.7, h: 1.3, rectRadius: 0.1, fill: { color: NAVY2 }, line: { color: "2E3E66", width: 1 } });
    s.addShape("ellipse", { x: x + 0.25, y: y + 0.45, w: 0.4, h: 0.4, fill: { color: AMBER } });
    s.addText(String(i + 1), { x: x + 0.25, y: y + 0.45, w: 0.4, h: 0.4, fontSize: 14, bold: true, color: NAVY, align: "center", valign: "middle" });
    s.addText(t, { x: x + 0.85, y: y + 0.15, w: 4.6, h: 1.0, fontSize: 13.5, color: "FFFFFF", valign: "middle" });
  });
}

// ---------------- Slide 4: Architecture ----------------
{
  const s = pres.addSlide();
  s.background = { color: CREAM };
  titleBar2(s, "System design", "Pipeline architecture");
  s.addImage({ path: "architecture.png", x: 4.15, y: 1.55, w: 4.9, h: 5.55 });
  const steps = [
    ["Parse", "Format-specific extraction from CSV, TXT, JSON, STIX"],
    ["Normalize", "Type detection + validation into one schema"],
    ["Correlate", "Cross-feed matching, severity by source count"],
    ["Export", "Blocklists + full dataset + summary report"],
  ];
  let y = 1.7;
  steps.forEach(([h, body]) => {
    s.addShape("rect", { x: 0.6, y, w: 0.06, h: 1.15, fill: { color: AMBER } });
    s.addText(h, { x: 0.85, y: y - 0.05, w: 3.1, h: 0.4, fontSize: 15, bold: true, color: NAVY });
    s.addText(body, { x: 0.85, y: y + 0.35, w: 3.1, h: 0.7, fontSize: 12, color: "5A5A54" });
    y += 1.35;
  });
}

// ---------------- Slide 5: Detection logic ----------------
{
  const s = pres.addSlide();
  s.background = { color: NAVY };
  titleBar(s, "How it decides", "Severity is source overlap, not guesswork");
  s.addText("No AI or ML - every decision is a deterministic, explainable rule.", { x: 0.7, y: 1.55, w: 11, h: 0.4, fontSize: 14, color: MUTED, italic: true });

  const rows = [
    ["3+ independent feeds", "HIGH", RED],
    ["2 independent feeds", "MEDIUM", AMBER],
    ["1 feed only", "LOW", "6B7A99"],
  ];
  let y = 2.3;
  rows.forEach(([label, sev, color]) => {
    s.addShape("roundRect", { x: 0.7, y, w: 8.2, h: 1.0, rectRadius: 0.08, fill: { color: NAVY2 }, line: { color: "2E3E66", width: 1 } });
    s.addText(label, { x: 1.0, y, w: 5.5, h: 1.0, fontSize: 15, color: "FFFFFF", valign: "middle" });
    s.addShape("roundRect", { x: 6.9, y: y + 0.25, w: 1.7, h: 0.5, rectRadius: 0.25, fill: { color } });
    s.addText(sev, { x: 6.9, y: y + 0.25, w: 1.7, h: 0.5, fontSize: 13, bold: true, color: NAVY, align: "center", valign: "middle" });
    y += 1.25;
  });
  s.addText("Blocklists are generated at MEDIUM+ severity only - a single low-confidence\nsource doesn't get pushed straight to a firewall rule without corroboration.", { x: 9.3, y: 2.3, w: 3.3, h: 3.0, fontSize: 12.5, color: MUTED, valign: "top" });
}

// ---------------- Slide 6: Results - by type ----------------
{
  const s = pres.addSlide();
  s.background = { color: CREAM };
  titleBar2(s, "Run results", "37 raw indicators -> 24 unique, validated IOCs");
  s.addImage({ path: "type_chart.png", x: 0.6, y: 1.6, w: 7.6, h: 4.6 });
  const stats = [["Feeds processed", "6"], ["Raw indicators", "37"], ["Rejected (invalid)", "2"], ["Unique after correlation", "24"]];
  let y = 1.9;
  stats.forEach(([label, val]) => {
    s.addText(val, { x: 8.6, y, w: 3.5, h: 0.55, fontSize: 26, bold: true, color: NAVY });
    s.addText(label, { x: 8.6, y: y + 0.55, w: 3.5, h: 0.35, fontSize: 12, color: "6B6B64" });
    y += 1.1;
  });
}

// ---------------- Slide 7: Results - severity + high priority ----------------
{
  const s = pres.addSlide();
  s.background = { color: CREAM };
  titleBar2(s, "Run results", "One indicator confirmed by three sources");
  s.addImage({ path: "analysis_chart.png", x: 0.6, y: 1.6, w: 5.4, h: 4.5 });

  const rows = [
    [{ text: "Type", options: { bold: true, fill: { color: NAVY }, color: "FFFFFF" } }, { text: "Value", options: { bold: true, fill: { color: NAVY }, color: "FFFFFF" } }, { text: "Sources", options: { bold: true, fill: { color: NAVY }, color: "FFFFFF" } }],
    ["ip", "185.220.101.45", "3 feeds (HIGH)"],
    ["domain", "malware-drop-zone.xyz", "2 feeds (MEDIUM)"],
    ["domain", "update-secure-check.com", "2 feeds (MEDIUM)"],
    ["md5", "5d41402a...017c592", "2 feeds (MEDIUM)"],
  ].map(r => Array.isArray(r) ? r.map(c => typeof c === "string" ? { text: c, options: { fontSize: 11 } } : c) : r);

  s.addTable(rows, { x: 6.3, y: 1.7, w: 6.4, colW: [1.3, 3.2, 1.9], fontSize: 11, border: { type: "solid", color: "D8D4C8", pt: 0.5 }, autoPage: false });
}

// ---------------- Slide 8: Deliverables ----------------
{
  const s = pres.addSlide();
  s.background = { color: NAVY };
  titleBar(s, "Output", "Deployable blocklist deliverables");
  const items = [
    ["blocklist_ips.txt", "3 IPs - firewall / IP-set format", TEAL],
    ["blocklist_web.txt", "3 domains, 0 URLs - web filter format", TEAL],
    ["blocklist_hashes.csv", "1 hash + algorithm - EDR/AV format", TEAL],
    ["blocklist_emails.txt", "Suspicious sender addresses (informational)", TEAL],
    ["ioc_dataset_full.json", "All 24 indicators incl. LOW - analyst archive", AMBER],
  ];
  let y = 1.85;
  items.forEach(([name, desc]) => {
    s.addShape("roundRect", { x: 0.7, y, w: 11.9, h: 0.85, rectRadius: 0.08, fill: { color: NAVY2 }, line: { color: "2E3E66", width: 1 } });
    s.addText(name, { x: 1.0, y, w: 3.6, h: 0.85, fontSize: 14, bold: true, color: TEAL, valign: "middle", fontFace: "Consolas" });
    s.addText(desc, { x: 4.7, y, w: 7.6, h: 0.85, fontSize: 13, color: "D6D9E2", valign: "middle" });
    y += 1.05;
  });
}

// ---------------- Slide 9: Conclusion ----------------
{
  const s = pres.addSlide();
  s.background = { color: CREAM };
  titleBar2(s, "Wrap-up", "What this project demonstrated");
  const points = [
    "Cross-feed correlation surfaces real signal: the one HIGH-severity IP was independently confirmed by 3 unrelated sources.",
    "Validation rules matter as much as parsing - two real bugs were caught by unit tests before manual testing, both edge cases in how 'valid' is defined.",
    "A minimum-severity threshold on blocklist generation keeps single-source noise out of firewall rules by default.",
  ];
  let y = 1.9;
  points.forEach((t, i) => {
    s.addShape("ellipse", { x: 0.7, y: y + 0.05, w: 0.45, h: 0.45, fill: { color: AMBER } });
    s.addText(String(i + 1), { x: 0.7, y: y + 0.05, w: 0.45, h: 0.45, fontSize: 15, bold: true, color: NAVY, align: "center", valign: "middle" });
    s.addText(t, { x: 1.35, y, w: 10.8, h: 0.9, fontSize: 15, color: "2C2C2A", valign: "middle" });
    y += 1.15;
  });
  s.addText("Code, tests, sample feeds, and generated blocklists are all in the project repository.", { x: 0.7, y: 6.5, w: 11.5, h: 0.5, fontSize: 12.5, italic: true, color: "6B6B64" });
}

function titleBar2(slide, kicker, title) {
  slide.addText(kicker.toUpperCase(), { x: 0.6, y: 0.35, w: 8, h: 0.35, fontSize: 12, color: "B85F1D", bold: true, charSpacing: 2 });
  slide.addText(title, { x: 0.6, y: 0.65, w: 11.5, h: 0.7, fontSize: 24, color: NAVY, bold: true });
}

pres.writeFile({ fileName: "TI_Aggregator_Presentation.pptx" }).then(() => console.log("PPTX written."));
