#!/usr/bin/env python3
"""
SuReader - a command-line tool for analysing Suricata EVE JSON alert logs.
Copyright (C) 2026  David Obi

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

Contact: David Obi — inque0017@gmail.com
Source code: https://github.com/TheVoidThatConsumes/SuReader

Usage:
    python main.py summary    elogs/eve.json
    python main.py top-ips    elogs/eve.json --count 10
    python main.py suspicious elogs/eve.json
    python main.py search     elogs/eve.json --ip 192.168.1.5
    python main.py triage     elogs/eve.json --assets assets.yml
    python main.py report     elogs/eve.json --export
"""

import argparse
import io
import ipaddress
import json
import os
import sys
import yaml
from collections import Counter, defaultdict
from datetime import datetime


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_LABELS    = {1: "High", 2: "Medium", 3: "Low"}
REPORTS_DIR        = "reports"
READ_BUFFER_BYTES  = 8 * 1024 * 1024
DEFAULT_ASSETS_FILE = "assets.yml"

# Triage scoring weights
CRITICALITY_SCORES = {"critical": 40, "high": 25, "medium": 10, "low": 0}
EXPOSURE_SCORES    = {"internet-facing": 30, "internal": 0}
SEVERITY_SCORES    = {1: 30, 2: 15, 3: 5}
CORRELATION_BONUS  = 25

# Tier thresholds
TIER_PAGE_NOW = 60
TIER_REVIEW   = 25


# ---------------------------------------------------------------------------
# Streaming loader
# ---------------------------------------------------------------------------

def iter_alerts(log_file):
    """
    The generator yields one alert event at a time without loading the
    whole file into memory while using an 8MB read buffer for performance.
    """
    try:
        with io.open(log_file, "r", encoding="utf-8", buffering=READ_BUFFER_BYTES) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("event_type") == "alert":
                    yield event
    except FileNotFoundError:
        print(f"[!] File not found: {log_file}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Single-pass analysis
# ---------------------------------------------------------------------------

def analyze(log_file):
    """
    Stream through the file once and collect aggregated stats.
    Returns a dict of Counters that all other commands read from.
    """
    total = 0
    sig_counts      = Counter()
    severity_counts = Counter()
    src_ip_counts   = Counter()
    dest_ip_counts  = Counter()
    proto_counts    = Counter()
    port_counts     = Counter()
    timeline        = Counter()
    src_ports       = defaultdict(set)
    src_sigs        = defaultdict(Counter)

    for event in iter_alerts(log_file):
        total += 1
        alert_block = event.get("alert", {})
        sig       = alert_block.get("signature", "Unknown signature")
        severity  = alert_block.get("severity", "Unknown")
        src_ip    = event.get("src_ip")
        dest_ip   = event.get("dest_ip")
        proto     = event.get("proto")
        dest_port = event.get("dest_port")

        sig_counts[sig] += 1
        severity_counts[severity] += 1
        if src_ip:              src_ip_counts[src_ip] += 1
        if dest_ip:             dest_ip_counts[dest_ip] += 1
        if proto:               proto_counts[proto] += 1
        if dest_port is not None: port_counts[dest_port] += 1

        ts_raw = event.get("timestamp", "")
        try:
            ts = datetime.strptime(ts_raw, "%Y-%m-%dT%H:%M:%S.%f%z")
            timeline[ts.strftime("%Y-%m-%d %H:00")] += 1
        except (ValueError, TypeError):
            timeline["unknown"] += 1

        if src_ip:
            if dest_port is not None:
                src_ports[src_ip].add(dest_port)
            src_sigs[src_ip][sig] += 1

    return {
        "total": total, "sig_counts": sig_counts,
        "severity_counts": severity_counts,
        "src_ip_counts": src_ip_counts, "dest_ip_counts": dest_ip_counts,
        "proto_counts": proto_counts, "port_counts": port_counts,
        "timeline": timeline, "src_ports": src_ports, "src_sigs": src_sigs,
    }


# ---------------------------------------------------------------------------
# Suspicious activity heuristics
# ---------------------------------------------------------------------------

def find_suspicious_activity(data, port_scan_threshold=10, signature_threshold=5):
    """
    Flag suspicious source IPs using three heuristics:
      1 - Port scan:   one IP hitting many distinct ports
      2 - Brute force: one IP repeating the same signature many times
      3 - Scanner:     one IP triggering many different signatures
    """
    findings = []

    for ip, ports in data["src_ports"].items():
        if len(ports) >= port_scan_threshold:
            findings.append({
                "type": "Possible port scan", "src_ip": ip,
                "detail": f"Hit {len(ports)} distinct destination ports",
            })

    for ip, sig_counts in data["src_sigs"].items():
        total    = sum(sig_counts.values())
        distinct = len(sig_counts)
        top_sig, top_count = sig_counts.most_common(1)[0]

        if top_count >= signature_threshold:
            findings.append({
                "type": "Possible brute-force / repeated probing", "src_ip": ip,
                "detail": f'Triggered "{top_sig}" {top_count} times',
            })

        if distinct >= signature_threshold and total >= signature_threshold:
            findings.append({
                "type": "Broad alert diversity (possible automated scanner)", "src_ip": ip,
                "detail": f"Triggered {distinct} different alert types ({total} alerts total)",
            })

    return findings


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

def search_alerts(log_file, ip=None, signature_keyword=None):
    """Stream and yield alerts matching the given IP or signature keyword."""
    kw = signature_keyword.lower() if signature_keyword else None
    for event in iter_alerts(log_file):
        src = event.get("src_ip")
        dst = event.get("dest_ip")
        if ip and src != ip and dst != ip:
            continue
        if kw:
            sig = event.get("alert", {}).get("signature", "")
            if kw not in sig.lower():
                continue
        yield event


# ---------------------------------------------------------------------------
# Asset context — CIDR-aware loader
# ---------------------------------------------------------------------------

def load_assets(assets_file=DEFAULT_ASSETS_FILE):
    """
    Load asset definitions from a YAML file.

    Supports both formats:
        CIDR-based  (enterprise style — matches whole subnets):
            assets:
              - name: "Data Center"
                cidr: "10.2.0.0/16"
                criticality: "critical"
                exposure: "internal"

        IP-based  (specific hosts):
            assets:
              10.0.0.5:
                name: "Primary DB"
                criticality: "critical"
                exposure: "internal"

    Returns a list of network entries, each with a compiled
    IPv4Network object for fast matching at triage time.
    """
    if not os.path.exists(assets_file):
        print(
            f"[!] No assets file found at {assets_file} — using defaults for all IPs.",
            file=sys.stderr,
        )
        return []

    with open(assets_file, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    raw_assets = raw.get("assets", [])
    networks   = []

    # Handle list-style (CIDR-based) assets.yml
    if isinstance(raw_assets, list):
        for entry in raw_assets:
            cidr = entry.get("cidr")
            if cidr:
                try:
                    networks.append({
                        "network":     ipaddress.IPv4Network(cidr, strict=False),
                        "name":        entry.get("name", cidr),
                        "criticality": entry.get("criticality", "low"),
                        "exposure":    entry.get("exposure", "internal"),
                    })
                except ValueError:
                    print(f"[!] Invalid CIDR in assets.yml: {cidr}", file=sys.stderr)

    # Handle dict-style (IP-keyed) assets.yml
    elif isinstance(raw_assets, dict):
        for ip, info in raw_assets.items():
            try:
                networks.append({
                    "network":     ipaddress.IPv4Network(f"{ip}/32", strict=False),
                    "name":        info.get("name", ip),
                    "criticality": info.get("criticality", "low"),
                    "exposure":    info.get("exposure", "internal"),
                })
            except ValueError:
                print(f"[!] Invalid IP in assets.yml: {ip}", file=sys.stderr)

    return networks


def asset_lookup(ip_str, networks):
    """
    Find the most specific matching network for an IP address.

    If multiple CIDRs match (e.g. 10.0.0.0/8 and 10.2.0.0/16 both
    match 10.2.0.5), the most specific one wins — longest prefix first.
    Returns (criticality, exposure, name) or defaults if no match.
    """
    if not ip_str:
        return "low", "internal", ip_str

    try:
        addr = ipaddress.IPv4Address(ip_str)
    except ValueError:
        return "low", "internal", ip_str

    matches = [n for n in networks if addr in n["network"]]
    if not matches:
        return "low", "internal", ip_str

    # Most specific match = longest prefix length
    best = max(matches, key=lambda n: n["network"].prefixlen)
    return best["criticality"], best["exposure"], best["name"]


# ---------------------------------------------------------------------------
# Triage scoring
# ---------------------------------------------------------------------------

def score_alert(event, networks, flagged_ips):
    """
    Score one alert from 0-125+ using four factors:

        Factor 1 — Asset criticality of the destination IP     (0-40)
        Factor 2 — Exposure of the destination IP               (0-30)
        Factor 3 — Suricata alert severity                      (0-30)
        Factor 4 — Source IP already flagged by heuristics      (0 or +25)

    Returns (score, tier, reasons). Reasons explain the score in plain
    English so a human reviewer understands why the alert was ranked.
    """
    alert_block = event.get("alert", {})
    severity    = alert_block.get("severity")
    src_ip      = event.get("src_ip")
    dest_ip     = event.get("dest_ip")

    score, reasons = 0, []

    # Factor 1 + 2: destination asset context via CIDR lookup
    criticality, exposure, asset_name = asset_lookup(dest_ip, networks)

    crit_pts = CRITICALITY_SCORES.get(criticality, 0)
    score += crit_pts
    if crit_pts > 0:
        reasons.append(
            f"destination matches '{asset_name}' (criticality={criticality}, +{crit_pts})"
        )

    exp_pts = EXPOSURE_SCORES.get(exposure, 0)
    score += exp_pts
    if exp_pts > 0:
        reasons.append(f"asset is internet-facing (+{exp_pts})")

    # Factor 3: Suricata severity
    sev_pts = SEVERITY_SCORES.get(severity, 0)
    score += sev_pts
    if sev_pts > 0:
        label = SEVERITY_LABELS.get(severity, str(severity))
        reasons.append(f"Suricata severity={label} (+{sev_pts})")

    # Factor 4: behavioural correlation
    if src_ip and src_ip in flagged_ips:
        score += CORRELATION_BONUS
        reasons.append(
            f"source IP {src_ip} already flagged by suspicious-activity scan (+{CORRELATION_BONUS})"
        )

    # Assign tier — nothing ever discarded
    if score >= TIER_PAGE_NOW:
        tier = "PAGE NOW"
    elif score >= TIER_REVIEW:
        tier = "REVIEW THIS SHIFT"
    else:
        tier = "LOG ONLY"

    return score, tier, reasons


def triage_alerts(log_file, assets_file=DEFAULT_ASSETS_FILE):
    """
    Full triage pipeline:
      1. Load CIDR-based asset definitions from assets.yml
      2. Reuse analyze() for aggregated data
      3. Reuse find_suspicious_activity() to get set of flagged source IPs
      4. Stream file again, scoring every individual alert
      5. Group into three tiers — nothing is ever discarded or suppressed
    """
    networks    = load_assets(assets_file)
    data        = analyze(log_file)
    findings    = find_suspicious_activity(data)
    flagged_ips = {f["src_ip"] for f in findings}

    tiers = {"PAGE NOW": [], "REVIEW THIS SHIFT": [], "LOG ONLY": []}

    for event in iter_alerts(log_file):
        score, tier, reasons = score_alert(event, networks, flagged_ips)
        tiers[tier].append((score, event, reasons))

    # Sort each tier by score descending — highest priority first
    for tier_name in tiers:
        tiers[tier_name].sort(key=lambda x: x[0], reverse=True)

    return tiers


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

def format_summary(data, n_sigs=10, n_ports=10):
    lines = []
    lines.append("=" * 60)
    lines.append("EVE LOG SUMMARY")
    lines.append("=" * 60)
    lines.append(f"Total alerts: {data['total']}")
    lines.append("")
    lines.append("Severity breakdown:")
    for sev, count in sorted(data["severity_counts"].items(), key=lambda x: str(x[0])):
        label = SEVERITY_LABELS.get(sev, str(sev))
        lines.append(f"  {label} ({sev}): {count}")
    lines.append("")
    lines.append(f"Top {n_sigs} alert signatures:")
    for sig, count in data["sig_counts"].most_common(n_sigs):
        lines.append(f"  [{count:>4}] {sig}")
    lines.append("")
    lines.append("Protocols seen:")
    for proto, count in data["proto_counts"].most_common():
        lines.append(f"  {proto}: {count}")
    lines.append("")
    lines.append(f"Top {n_ports} targeted destination ports:")
    for port, count in data["port_counts"].most_common(n_ports):
        lines.append(f"  Port {port}: {count}")
    lines.append("")
    lines.append("Alert timeline (per hour):")
    sorted_keys = sorted(k for k in data["timeline"] if k != "unknown")
    for key in sorted_keys:
        lines.append(f"  {key}: {data['timeline'][key]}")
    if "unknown" in data["timeline"]:
        lines.append(f"  unknown: {data['timeline']['unknown']}")
    lines.append("")
    return lines


def format_top_ips(data, n=10):
    lines = []
    lines.append("=" * 60)
    lines.append(f"TOP {n} SOURCE / DESTINATION IPs")
    lines.append("=" * 60)
    lines.append("Top source IPs (most alerts triggered):")
    for ip, count in data["src_ip_counts"].most_common(n):
        lines.append(f"  [{count:>4}] {ip}")
    lines.append("")
    lines.append("Top destination IPs (most alerts received):")
    for ip, count in data["dest_ip_counts"].most_common(n):
        lines.append(f"  [{count:>4}] {ip}")
    lines.append("")
    return lines


def format_suspicious(data):
    lines = []
    lines.append("=" * 60)
    lines.append("SUSPICIOUS ACTIVITY FINDINGS")
    lines.append("=" * 60)
    findings = find_suspicious_activity(data)
    if not findings:
        lines.append("No suspicious patterns detected with current thresholds.")
    else:
        for f in findings:
            lines.append(f"[{f['type']}]")
            lines.append(f"  Source IP : {f['src_ip']}")
            lines.append(f"  Detail    : {f['detail']}")
            lines.append("")
    return lines


def format_search_results(results):
    rows = []
    for event in results:
        sig      = event.get("alert", {}).get("signature", "Unknown signature")
        severity = event.get("alert", {}).get("severity", "?")
        rows.append(
            f"{event.get('timestamp', '?')} | "
            f"{event.get('src_ip', '?')}:{event.get('src_port', '?')} -> "
            f"{event.get('dest_ip', '?')}:{event.get('dest_port', '?')} "
            f"[{event.get('proto', '?')}] (severity {severity}) {sig}"
        )
    lines = []
    lines.append("=" * 60)
    lines.append(f"SEARCH RESULTS ({len(rows)} matches)")
    lines.append("=" * 60)
    lines.extend(rows)
    return lines


def format_triage(tiers, max_per_tier=20):
    """
    Format the triage report. Every alert appears in exactly one tier.
    No alerts are discarded — LOG ONLY entries are still fully listed.
    """
    lines = []
    lines.append("=" * 60)
    lines.append("ALERT TRIAGE REPORT")
    lines.append("=" * 60)

    total = sum(len(v) for v in tiers.values())
    lines.append(f"Total alerts triaged: {total}")
    lines.append(f"  PAGE NOW           : {len(tiers['PAGE NOW'])}")
    lines.append(f"  REVIEW THIS SHIFT  : {len(tiers['REVIEW THIS SHIFT'])}")
    lines.append(f"  LOG ONLY           : {len(tiers['LOG ONLY'])}")
    lines.append("")
    lines.append("Scoring: asset criticality + exposure + Suricata severity + behavioural correlation.")
    lines.append("No alerts are discarded. LOG ONLY alerts are deprioritised, not deleted.")
    lines.append("")

    for tier_name in ["PAGE NOW", "REVIEW THIS SHIFT", "LOG ONLY"]:
        entries = tiers[tier_name]
        lines.append("-" * 60)
        lines.append(f"[{tier_name}]  ({len(entries)} alerts)")
        lines.append("-" * 60)

        if not entries:
            lines.append("  (none)")
            lines.append("")
            continue

        shown = entries[:max_per_tier]
        for score, event, reasons in shown:
            sig = event.get("alert", {}).get("signature", "Unknown signature")
            src = event.get("src_ip", "?")
            dst = event.get("dest_ip", "?")
            ts  = event.get("timestamp", "?")
            lines.append(f"  [score {score:>3}] {ts}")
            lines.append(f"    {src} -> {dst}  |  {sig}")
            for reason in reasons:
                lines.append(f"      - {reason}")
            lines.append("")

        remaining = len(entries) - len(shown)
        if remaining > 0:
            lines.append(
                f"  ... and {remaining} more in this tier. "
                f"Use --export to save the full list."
            )
            lines.append("")

    return lines


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def output_lines(lines, export_name=None):
    text = "\n".join(lines)
    print(text)

    if export_name is not None:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        if export_name is True:
            timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
            export_name = f"report_{timestamp}.txt"
        export_path = os.path.join(REPORTS_DIR, export_name)
        try:
            with open(export_path, "w", encoding="utf-8") as f:
                f.write(text + "\n")
            print(f"\n[+] Report saved to {export_path}")
        except OSError as e:
            print(f"[!] Failed to write report: {e}", file=sys.stderr)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Analyze Suricata EVE JSON alert logs."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    export_help = (
        "Save to reports/ folder. "
        "Use alone for auto-named file, or give a filename: --export myreport.txt"
    )

    p_summary = subparsers.add_parser("summary", help="Show overall alert summary")
    p_summary.add_argument("log_file")
    p_summary.add_argument("--export", nargs="?", const=True, metavar="FILENAME", help=export_help)

    p_top = subparsers.add_parser("top-ips", help="Show top source/destination IPs")
    p_top.add_argument("log_file")
    p_top.add_argument("--count", type=int, default=10,
                        help="Number of IPs to show (default: 10)")
    p_top.add_argument("--export", nargs="?", const=True, metavar="FILENAME", help=export_help)

    p_suspicious = subparsers.add_parser("suspicious", help="Flag suspicious activity")
    p_suspicious.add_argument("log_file")
    p_suspicious.add_argument("--export", nargs="?", const=True, metavar="FILENAME", help=export_help)

    p_search = subparsers.add_parser("search", help="Search/filter alerts")
    p_search.add_argument("log_file")
    p_search.add_argument("--ip")
    p_search.add_argument("--signature")
    p_search.add_argument("--export", nargs="?", const=True, metavar="FILENAME", help=export_help)

    p_triage = subparsers.add_parser("triage", help="Score and rank alerts by real-world risk")
    p_triage.add_argument("log_file")
    p_triage.add_argument(
        "--assets", default=DEFAULT_ASSETS_FILE,
        help=f"Path to assets YAML file (default: {DEFAULT_ASSETS_FILE})",
    )
    p_triage.add_argument(
        "--max-per-tier", type=int, default=20,
        help="Max alerts shown per tier in terminal output (default: 20)",
    )
    p_triage.add_argument("--export", nargs="?", const=True, metavar="FILENAME", help=export_help)

    p_report = subparsers.add_parser("report", help="Generate full combined report")
    p_report.add_argument("log_file")
    p_report.add_argument("--export", nargs="?", const=True, metavar="FILENAME", help=export_help)

    args = parser.parse_args()

    # search and triage manage their own data flow — handle before
    # the shared analyze() call so the file isn't processed twice.

    if args.command == "search":
        if not args.ip and not args.signature:
            print("[!] Provide at least --ip or --signature.", file=sys.stderr)
            sys.exit(1)
        results = search_alerts(args.log_file, ip=args.ip, signature_keyword=args.signature)
        output_lines(format_search_results(results), args.export)
        return

    if args.command == "triage":
        tiers = triage_alerts(args.log_file, assets_file=args.assets)
        output_lines(
            format_triage(tiers, max_per_tier=args.max_per_tier),
            args.export,
        )
        return

    data = analyze(args.log_file)

    if data["total"] == 0:
        print("[!] No alert events found in log file.", file=sys.stderr)
        sys.exit(1)

    if args.command == "summary":
        output_lines(format_summary(data), args.export)
    elif args.command == "top-ips":
        output_lines(format_top_ips(data, n=args.count), args.export)
    elif args.command == "suspicious":
        output_lines(format_suspicious(data), args.export)
    elif args.command == "report":
        lines = []
        lines.extend(format_summary(data))
        lines.extend(format_top_ips(data))
        lines.extend(format_suspicious(data))
        output_lines(lines, args.export)


if __name__ == "__main__":
    main()