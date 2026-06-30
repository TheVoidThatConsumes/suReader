#!/usr/bin/env python3
"""
EVE Analyzer - A CLI tool for analyzing Suricata EVE JSON alert logs.

Usage:
    python main.py summary elogs/(filename).json
    python main.py top-ips elogs/(filename).json --count 10
    python main.py suspicious elogs/(filename).json
    python main.py search elogs/(filename).json --ip (IP_ADDRESS)
    python main.py report elogs/(filename).json --export
    python main.py triage elogs/(filename).json
    python main.py triage elogs/(filename).json --export myreport.txt
    python main.py triage elogs/(filename).json --assets assets.yml --export myreport.txt
"""

import argparse
import io
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime
from ipaddress import AddressValueError, ip_address, ip_network


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_LABELS = {1: "High", 2: "Medium", 3: "Low"}
REPORTS_DIR = "reports"
DEFAULT_ASSETS_FILE = "assets.yml"

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


def parse_yaml_scalar(value):
    value = value.strip()
    if value in ("null", "none", "None", "~"):
        return None
    lowered = value.lower()
    if lowered in ("true", "false"):
        return lowered == "true"
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value.strip('"').strip("'")


def load_assets(assets_file=None):
    path = assets_file or DEFAULT_ASSETS_FILE
    if not path or not os.path.exists(path):
        return []

    assets = []
    current = None
    root_key = None

    with io.open(path, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.rstrip("\n")
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            indent = len(line) - len(line.lstrip(" "))
            if indent == 0 and stripped.endswith(":"):
                root_key = stripped[:-1].strip()
                continue

            if root_key != "assets":
                continue

            if stripped.startswith("-"):
                if current is not None:
                    assets.append(current)
                current = {}
                remainder = stripped[1:].strip()
                if remainder and ":" in remainder:
                    key, value = remainder.split(":", 1)
                    current[key.strip()] = parse_yaml_scalar(value)
                continue

            if current is None:
                continue

            if ":" in stripped:
                key, value = stripped.split(":", 1)
                current[key.strip()] = parse_yaml_scalar(value)

    if current is not None:
        assets.append(current)

    normalized = []
    for asset in assets:
        normalized_asset = {
            "name": asset.get("name", "Unnamed asset"),
            "ip": asset.get("ip"),
            "cidr": asset.get("cidr"),
            "criticality": str(asset.get("criticality", "unknown")).strip().lower(),
            "exposure": str(asset.get("exposure", "unknown")).strip().lower(),
        }
        normalized.append(normalized_asset)

    return normalized


def match_asset_for_ip(ip, assets):
    if not ip or not assets:
        return None

    try:
        parsed_ip = ip_address(ip)
    except ValueError:
        return None

    exact_match = next((a for a in assets if a.get("ip") == ip), None)
    if exact_match:
        return exact_match

    for asset in assets:
        cidr = asset.get("cidr")
        if not cidr:
            continue
        try:
            if parsed_ip in ip_network(cidr, strict=False):
                return asset
        except (AddressValueError, ValueError):
            continue

    return None


def normalize_severity(severity):
    if isinstance(severity, int):
        return severity
    if isinstance(severity, str):
        s = severity.strip().lower()
        if s.isdigit():
            return int(s)
        if s in ("critical", "high"):
            return 1
        if s in ("medium", "med"):
            return 2
        if s in ("low", "info", "informational"):
            return 3
    return 3


def signature_risk_weight(signature):
    if not signature:
        return 0
    sig = signature.lower()
    weights = 0
    high_risk = [
        "ransomware",
        "cobalt strike",
        "meterpreter",
        "shellcode",
        "exploit",
        "privilege escalation",
        "sql injection",
        "command injection",
        "remote code execution",
        "unauthorized access",
        "brute force",
        "password spraying",
        "malware",
        "botnet",
        "backdoor",
        "c2 server",
    ]
    moderate_risk = [
        "scanner",
        "port scan",
        "suspicious",
        "unauthenticated",
        "traffic anomaly",
        "dos",
        "ddos",
        "sqli",
        "xss",
    ]
    for keyword in high_risk:
        if keyword in sig:
            return 15
    for keyword in moderate_risk:
        if keyword in sig:
            weights = max(weights, 8)
    return weights


def port_risk_weight(port):
    try:
        port = int(port)
    except (TypeError, ValueError):
        return 0

    critical_ports = {22, 23, 80, 443, 3389, 3306, 1433, 1521, 5985, 5900, 8080}
    sensitive_ports = {53, 111, 137, 139, 445, 514, 873, 5000, 5001, 11211}
    if port in critical_ports:
        return 12
    if port in sensitive_ports:
        return 8
    if 1 <= port <= 1024:
        return 5
    return 2


def get_asset_weight(asset):
    if not asset:
        return 15

    criticality_weights = {
        "critical": 45,
        "high": 35,
        "medium": 25,
        "low": 15,
        "unknown": 15,
    }
    exposure_weights = {
        "internet-facing": 35,
        "internet": 30,
        "external": 25,
        "dmz": 20,
        "internal": 15,
        "honeypot": 20,
        "unknown": 15,
    }
    return (
        criticality_weights.get(asset.get("criticality", "unknown"), 15)
        + exposure_weights.get(asset.get("exposure", "unknown"), 15)
    )


def compute_suspicion_scores(data, port_scan_threshold=10, signature_threshold=5):
    suspicion_scores = {}

    for ip, ports in data["src_ports"].items():
        score = 0
        reasons = []
        distinct_ports = len(ports)
        if distinct_ports >= port_scan_threshold:
            score += 25 + max(0, distinct_ports - port_scan_threshold) * 2
            reasons.append(f"port scan ({distinct_ports} distinct ports)")
        suspicion_scores[ip] = {"score": score, "reasons": reasons}

    for ip, sig_counts in data["src_sigs"].items():
        entry = suspicion_scores.setdefault(ip, {"score": 0, "reasons": []})
        total = sum(sig_counts.values())
        distinct = len(sig_counts)
        top_sig, top_count = sig_counts.most_common(1)[0]

        if top_count >= signature_threshold:
            entry["score"] += 18 + max(0, top_count - signature_threshold) * 2
            entry["reasons"].append(f"repeated '{top_sig}' {top_count} times")

        if distinct >= signature_threshold and total >= signature_threshold:
            entry["score"] += 18 + max(0, distinct - signature_threshold) * 2
            entry["reasons"].append(
                f"diverse signatures ({distinct} different, {total} total alerts)"
            )

        if total >= 25:
            entry["score"] += 10
            entry["reasons"].append(f"high alert volume ({total} alerts)")

    return suspicion_scores


def score_alert_for_triage(event, asset, suspicion):
    severity = normalize_severity(event.get("alert", {}).get("severity"))
    severity_weight = {1: 40, 2: 30, 3: 20}.get(severity, 20)

    signature = event.get("alert", {}).get("signature", "")
    signature_weight = signature_risk_weight(signature)
    port_weight = port_risk_weight(event.get("dest_port"))
    asset_weight = get_asset_weight(asset)
    suspicion_weight = suspicion.get("score", 0)

    score = asset_weight + severity_weight + suspicion_weight + signature_weight + port_weight
    if not asset:
        score += 5

    return {
        "score": score,
        "asset_name": asset.get("name") if asset else "Unknown asset",
        "asset_criticality": asset.get("criticality", "unknown") if asset else "unknown",
        "asset_exposure": asset.get("exposure", "unknown") if asset else "unknown",
        "suspicion_reasons": suspicion.get("reasons", []),
    }


def categorize_triage_entries(entries):
    buckets = {
        "Page now": [],
        "Review this shift": [],
        "Log only": [],
    }

    for entry in entries:
        if entry["score"] >= 80:
            buckets["Page now"].append(entry)
        elif entry["score"] >= 55:
            buckets["Review this shift"].append(entry)
        else:
            buckets["Log only"].append(entry)

    return buckets


def triage(log_file, assets_file=None):
    assets = load_assets(assets_file)
    data = analyze(log_file)
    suspicion_map = compute_suspicion_scores(data)

    triage_entries = []
    for event in iter_alerts(log_file):
        src_ip = event.get("src_ip")
        dest_ip = event.get("dest_ip")
        asset = match_asset_for_ip(dest_ip, assets) or match_asset_for_ip(src_ip, assets)
        suspicion = suspicion_map.get(src_ip, {"score": 0, "reasons": []})
        scored = score_alert_for_triage(event, asset, suspicion)

        triage_entries.append(
            {
                "score": scored["score"],
                "timestamp": event.get("timestamp", "?")[:19],
                "src_ip": src_ip or "?",
                "dest_ip": dest_ip or "?",
                "dest_port": event.get("dest_port", "?"),
                "proto": event.get("proto", "?"),
                "signature": event.get("alert", {}).get("signature", "Unknown signature"),
                "severity": event.get("alert", {}).get("severity", "?") ,
                "asset_name": scored["asset_name"],
                "asset_criticality": scored["asset_criticality"],
                "asset_exposure": scored["asset_exposure"],
                "suspicion_reasons": scored["suspicion_reasons"],
            }
        )

    triage_entries.sort(key=lambda x: x["score"], reverse=True)
    return {
        "assets_loaded": len(assets),
        "alerts_processed": len(triage_entries),
        "buckets": categorize_triage_entries(triage_entries),
    }


def format_triage_report(report):
    lines = []
    lines.append("=" * 100)
    lines.append("EVE TRIAGE REPORT".center(100))
    lines.append("=" * 100)
    lines.append(f"Alerts processed: {report['alerts_processed']}".ljust(50) + f"Assets loaded: {report['assets_loaded']}")
    lines.append("")

    for tier in ("Page now", "Review this shift", "Log only"):
        entries = report["buckets"][tier]
        lines.append("-" * 100)
        lines.append(f"{tier} ({len(entries)} alerts)")
        lines.append("-" * 100)
        if not entries:
            lines.append("  None")
        else:
            lines.append(
                "  "
                + "Score".rjust(5)
                + "  "
                + "Timestamp".ljust(19)
                + "  "
                + "Src -> Dst:Port".ljust(38)
                + "  "
                + "Proto".ljust(5)
                + "  "
                + "Sev".ljust(3)
                + "  "
                + "Asset (crit/exposure)"
            )
            lines.append("  " + "-" * 94)
            for entry in entries:
                reason_text = "; ".join(entry["suspicion_reasons"]) or "none"
                src_dest = f"{entry['src_ip']}->{entry['dest_ip']}:{entry['dest_port']}"
                asset_meta = f"{entry['asset_name']}({entry['asset_criticality']}/{entry['asset_exposure']})"
                lines.append(
                    "  "
                    + f"{entry['score']:>5}"
                    + "  "
                    + f"{entry['timestamp']:<19}"
                    + "  "
                    + f"{src_dest:<38}"
                    + "  "
                    + f"{entry['proto']:<5}"
                    + "  "
                    + f"{str(entry['severity']):<3}"
                    + "  "
                    + asset_meta
                )
                lines.append(f"      reason: {reason_text}")
                lines.append("")
        lines.append("")

    return lines


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
    lines.append("=" * 80)
    lines.append("EVE LOG SUMMARY".center(80))
    lines.append("=" * 80)
    lines.append(f"Total alerts: {data['total']}".ljust(40) + f"Unique signatures: {len(data['sig_counts'])}")
    lines.append("")

    lines.append("Severity breakdown:")
    lines.append("  " + "Severity".ljust(15) + "Count")
    lines.append("  " + "-" * 24)
    for sev, count in sorted(data["severity_counts"].items(), key=lambda x: str(x[0])):
        label = SEVERITY_LABELS.get(sev, str(sev))
        lines.append(f"  {label:<15}{count}")
    lines.append("")

    lines.append(f"Top {n_sigs} alert signatures:")
    lines.append("  " + "Count".rjust(6) + "  Signature")
    lines.append("  " + "-" * 70)
    for sig, count in data["sig_counts"].most_common(n_sigs):
        lines.append(f"  {count:>6}  {sig}")
    lines.append("")

    lines.append("Protocols seen:")
    lines.append("  " + "Protocol".ljust(15) + "Count")
    lines.append("  " + "-" * 24)
    for proto, count in data["proto_counts"].most_common():
        lines.append(f"  {proto:<15}{count}")
    lines.append("")

    lines.append(f"Top {n_ports} targeted destination ports:")
    lines.append("  " + "Port".ljust(8) + "Count")
    lines.append("  " + "-" * 20)
    for port, count in data["port_counts"].most_common(n_ports):
        lines.append(f"  {str(port):<8}{count}")
    lines.append("")

    lines.append("Alert timeline (per hour):")
    lines.append("  " + "Hour".ljust(20) + "Count")
    lines.append("  " + "-" * 30)
    sorted_keys = sorted(k for k in data["timeline"] if k != "unknown")
    for key in sorted_keys:
        lines.append(f"  {key:<20}{data['timeline'][key]}")
    if "unknown" in data["timeline"]:
        lines.append(f"  {'unknown':<20}{data['timeline']['unknown']}")
    lines.append("")

    return lines


def format_top_ips(data, n=10):
    lines = []
    lines.append("=" * 80)
    lines.append(f"TOP {n} SOURCE / DESTINATION IPs".center(80))
    lines.append("=" * 80)

    lines.append("Top source IPs (most alerts triggered):")
    lines.append("  " + "Count".rjust(6) + "  Source IP")
    lines.append("  " + "-" * 50)
    for ip, count in data["src_ip_counts"].most_common(n):
        lines.append(f"  {count:>6}  {ip}")
    lines.append("")

    lines.append("Top destination IPs (most alerts received):")
    lines.append("  " + "Count".rjust(6) + "  Destination IP")
    lines.append("  " + "-" * 50)
    for ip, count in data["dest_ip_counts"].most_common(n):
        lines.append(f"  {count:>6}  {ip}")
    lines.append("")

    return lines


def format_suspicious(data):
    lines = []
    lines.append("=" * 80)
    lines.append("SUSPICIOUS ACTIVITY FINDINGS".center(80))
    lines.append("=" * 80)

    findings = find_suspicious_activity(data)
    if not findings:
        lines.append("No suspicious patterns detected with current thresholds.")
        lines.append("")
    else:
        lines.append("  " + "Type".ljust(42) + "Source IP".ljust(20) + "Detail")
        lines.append("  " + "-" * 75)
        for f in findings:
            lines.append(f"  {f['type']:<42}{f['src_ip']:<20}{f['detail']}")
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
    lines.append(f"SEARCH RESULTS ({len(rows)} matches)")  # count known now
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
        if export_name is True:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            export_name = f"report_{timestamp}.txt"

        os.makedirs(REPORTS_DIR, exist_ok=True)
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
    p_top.add_argument("--count", type=int, default=10)
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

    p_triage = subparsers.add_parser("triage", help="Score alerts and generate a three-tier triage report")
    p_triage.add_argument("log_file")
    p_triage.add_argument(
        "--assets",
        default=DEFAULT_ASSETS_FILE,
        metavar="PATH",
        help="Optional path to assets.yml defining asset criticality and exposure (defaults to assets.yml)",
    )
    p_triage.add_argument(
        "--export",
        nargs="?",
        const=True,
        default=True,
        metavar="FILENAME",
        help="Save triage output to reports/ by default; optionally provide a filename",
    )

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

    elif args.command == "triage":
        report = triage(args.log_file, assets_file=args.assets)
        output_lines(format_triage_report(report), args.export)


if __name__ == "__main__":
    main()