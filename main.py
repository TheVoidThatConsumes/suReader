#!/usr/bin/env python3
"""
EVE Analyzer - A CLI tool for analyzing Suricata EVE JSON alert logs.

Usage:
    python main.py summary elogs/(filename).json
    python main.py top-ips elogs/(filename).json --n 10
    python main.py suspicious elogs/(filename).json
    python main.py search elogs/(filename).json --ip (IP_ADDRESS)
    python main.py report elogs/(filename).json --export
"""

import argparse
import io
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_LABELS = {1: "High", 2: "Medium", 3: "Low"}
REPORTS_DIR = "reports"

# Read the file in 8MB chunks rather than the default ~8KB.
# For a 700MB file this cuts the number of read() syscalls from ~87,000
# down to ~88, which meaningfully reduces I/O overhead.
READ_BUFFER_BYTES = 8 * 1024 * 1024


# ---------------------------------------------------------------------------
# Streaming loader
# ---------------------------------------------------------------------------

def iter_alerts(log_file):
    """
    Generator: open the eve.json file and yield one alert event at a time.

    A generator means the entire file is never held in memory at once.
    Each line is parsed and, if it is an alert event, yielded to the caller.
    Lines that are empty or contain broken JSON are skipped silently.

    Using io.open with a large buffer (READ_BUFFER_BYTES) means Python
    reads big chunks from disk at once rather than many small reads,
    which is the main speed gain for large files.
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
    Stream through the file once only and collect everything we need (signatures, IPs,
    ports, timeline, suspicious activity), then returns a dict of accumulators that the formatting functions read from.
    """
    
    total = 0
    sig_counts     = Counter()
    severity_counts = Counter()
    src_ip_counts  = Counter()
    dest_ip_counts = Counter()
    proto_counts   = Counter()
    port_counts    = Counter()
    timeline       = Counter()

    # For suspicious-activity heuristics we track per-source-IP state.
    src_ports      = defaultdict(set)
    src_sigs       = defaultdict(Counter)

    for event in iter_alerts(log_file):
        total += 1

        alert_block = event.get("alert", {})
        sig      = alert_block.get("signature", "Unknown signature")
        severity = alert_block.get("severity", "Unknown")
        src_ip   = event.get("src_ip")
        dest_ip  = event.get("dest_ip")
        proto    = event.get("proto")
        dest_port = event.get("dest_port")

        sig_counts[sig] += 1
        severity_counts[severity] += 1

        if src_ip:
            src_ip_counts[src_ip] += 1
        if dest_ip:
            dest_ip_counts[dest_ip] += 1
        if proto:
            proto_counts[proto] += 1
        if dest_port is not None:
            port_counts[dest_port] += 1

        # Timeline bucketed by hour
        ts_raw = event.get("timestamp", "")
        try:
            ts = datetime.strptime(ts_raw, "%Y-%m-%dT%H:%M:%S.%f%z")
            timeline[ts.strftime("%Y-%m-%d %H:00")] += 1
        except (ValueError, TypeError):
            timeline["unknown"] += 1

        # Heuristic data
        if src_ip:
            if dest_port is not None:
                src_ports[src_ip].add(dest_port)
            src_sigs[src_ip][sig] += 1

    return {
        "total":          total,
        "sig_counts":     sig_counts,
        "severity_counts": severity_counts,
        "src_ip_counts":  src_ip_counts,
        "dest_ip_counts": dest_ip_counts,
        "proto_counts":   proto_counts,
        "port_counts":    port_counts,
        "timeline":       timeline,
        "src_ports":      src_ports,
        "src_sigs":       src_sigs,
    }


# ---------------------------------------------------------------------------
# Suspicious activity heuristics
# ---------------------------------------------------------------------------

def find_suspicious_activity(data, port_scan_threshold=10, signature_threshold=5):
    """
    Apply three simple heuristics to flag suspicious source IPs.

    Works on the pre-built src_ports and src_sigs dicts from analyze(),
    so no extra file pass is needed.

    Heuristic 1 - Port scan:   one IP hitting many distinct ports.
    Heuristic 2 - Brute force: one IP repeating the same signature many times.
    Heuristic 3 - Scanner:     one IP triggering many different signatures.
    """
    findings = []

    for ip, ports in data["src_ports"].items():
        if len(ports) >= port_scan_threshold:
            findings.append({
                "type":   "Possible port scan",
                "src_ip": ip,
                "detail": f"Hit {len(ports)} distinct destination ports",
            })

    for ip, sig_counts in data["src_sigs"].items():
        total        = sum(sig_counts.values())
        distinct     = len(sig_counts)
        top_sig, top_count = sig_counts.most_common(1)[0]

        if top_count >= signature_threshold:
            findings.append({
                "type":   "Possible brute-force / repeated probing",
                "src_ip": ip,
                "detail": f'Triggered "{top_sig}" {top_count} times',
            })

        if distinct >= signature_threshold and total >= signature_threshold:
            findings.append({
                "type":   "Broad alert diversity (possible automated scanner)",
                "src_ip": ip,
                "detail": f"Triggered {distinct} different alert types ({total} alerts total)",
            })

    return findings


# ---------------------------------------------------------------------------
# Search  (only command that still streams — results printed as they match)
# ---------------------------------------------------------------------------

def search_alerts(log_file, ip=None, signature_keyword=None):
    """
    Stream through the file and yield matching alerts.

    Search is kept as a separate streaming pass because it only needs
    matching events, not the full aggregated picture.
    """
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
    lines = []
    lines.append("=" * 60)
    count = 0
    rows = []
    for event in results:
        count += 1
        sig      = event.get("alert", {}).get("signature", "Unknown signature")
        severity = event.get("alert", {}).get("severity", "?")
        rows.append(
            f"{event.get('timestamp', '?')} | "
            f"{event.get('src_ip', '?')}:{event.get('src_port', '?')} -> "
            f"{event.get('dest_ip', '?')}:{event.get('dest_port', '?')} "
            f"[{event.get('proto', '?')}] (severity {severity}) {sig}"
        )
    lines.append(f"SEARCH RESULTS ({count} matches)")
    lines.append("=" * 60)
    lines.extend(rows)
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
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
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
    p_top.add_argument("--n", type=int, default=10)
    p_top.add_argument("--export", nargs="?", const=True, metavar="FILENAME", help=export_help)

    p_suspicious = subparsers.add_parser("suspicious", help="Flag suspicious activity")
    p_suspicious.add_argument("log_file")
    p_suspicious.add_argument("--export", nargs="?", const=True, metavar="FILENAME", help=export_help)

    p_search = subparsers.add_parser("search", help="Search/filter alerts")
    p_search.add_argument("log_file")
    p_search.add_argument("--ip")
    p_search.add_argument("--signature")
    p_search.add_argument("--export", nargs="?", const=True, metavar="FILENAME", help=export_help)

    p_report = subparsers.add_parser("report", help="Generate full combined report")
    p_report.add_argument("log_file")
    p_report.add_argument("--export", nargs="?", const=True, metavar="FILENAME", help=export_help)

    args = parser.parse_args()

    if args.command == "search":
        if not args.ip and not args.signature:
            print("[!] Provide at least --ip or --signature to search.", file=sys.stderr)
            sys.exit(1)
        results = search_alerts(args.log_file, ip=args.ip, signature_keyword=args.signature)
        output_lines(format_search_results(results), args.export)
        return

    # All other commands need the full single-pass analysis
    data = analyze(args.log_file)

    if data["total"] == 0:
        print("[!] No alert events found in log file.", file=sys.stderr)

    if args.command == "summary":
        output_lines(format_summary(data), args.export)

    elif args.command == "top-ips":
        output_lines(format_top_ips(data, n=args.n), args.export)

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