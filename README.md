# suReader

A command-line tool for analysing Suricata EVE JSON alert logs.

Designed to handle large log files (700MB+) efficiently using a streaming
architecture — the file is read once and never fully loaded into memory.

---

## What it does

| Command | What it shows |
|---|---|
| `summary` | Total alerts, severity breakdown, top signatures, protocols, ports, hourly timeline |
| `top-ips` | Top source and destination IPs by alert count |
| `suspicious` | IPs flagged for port scanning, brute-force, or automated scanning behaviour |
| `search` | Filter alerts by IP address or signature keyword |
| `report` | Full combined output of all three analysis views |

All commands support `--export` to save the output as a `.txt` file in the `reports/` folder.

---

## Requirements

- Python 3.10 or higher
- No external dependencies — standard library only

---

## Setup

1. Clone or download this repository
2. Two demo log files are already included in the `elogs/` folder:
   - `elogs/honeypot.json` — real honeypot traffic captures
   - `elogs/conference.json` — network traffic from a security conference
3. Run any command directly with Python — no install needed

```
elogs/
  honeypot.json      ← included demo file
  conference.json    ← included demo file
reports/             ← exported reports saved here automatically
main.py
README.md
```

---

## Usage

```bash
# try it immediately with the included demo files
python main.py summary    elogs/honeypot.json
python main.py top-ips    elogs/conference.json --count 10
python main.py suspicious elogs/honeypot.json
python main.py search     elogs/honeypot.json --ip 192.168.1.5
python main.py search     elogs/conference.json --signature "ET SCAN"
python main.py report     elogs/honeypot.json
```

### Exporting reports

```bash
# auto-named with timestamp
python main.py summary elogs/honeypot.json --export

# custom filename
python main.py summary elogs/honeypot.json --export my_summary.txt

# full report exported
python main.py report elogs/honeypot.json --export full_report.txt
```

Reports are always saved to the `reports/` folder, which is created
automatically if it does not exist.

---

## Using your own log files

Place any Suricata EVE JSON log file in the `elogs/` folder and run the
same commands against it.

If you do not have a Suricata instance running, you can use the following sources
provide real EVE JSON logs for analysis and research:

- **Malware Traffic Analysis** — real packet captures with EVE logs from malware infections
  https://www.malware-traffic-analysis.net

- **PCAP samples with Suricata output** — community-maintained collection of network captures
  https://www.netresec.com/?page=PcapFiles

- **Evebox sample datasets** — EVE JSON files shared alongside the Evebox SIEM project
  https://github.com/jasonish/evebox

- **Suricata documentation test files** — official sample logs from the Suricata project
  https://suricata.io/download

- **SecurityOnion sample data** — EVE JSON logs included with the SecurityOnion distribution
  https://securityonionsolutions.com

To generate your own EVE logs, install Suricata and run it against any
`.pcap` file with `suricata -r yourfile.pcap`. Suricata produces
`eve.json` in its log directory automatically.

---

## Example output

```
============================================================
EVE LOG SUMMARY
============================================================
Total alerts: 48,921

Severity breakdown:
  High (1): 3,204
  Medium (2): 31,445
  Low (3): 14,272

Top 10 alert signatures:
  [8431] ET SCAN Nmap Scripting Engine User-Agent Detected
  [6102] ET POLICY PE EXE or DLL Windows file download
  ...

Protocols seen:
  TCP: 41,203
  UDP: 7,718

Alert timeline (per hour):
  2024-01-15 08:00: 1,204
  2024-01-15 09:00: 3,891
  ...
```

```
============================================================
SUSPICIOUS ACTIVITY FINDINGS
============================================================
[Possible port scan]
  Source IP : 203.0.113.45
  Detail    : Hit 47 distinct destination ports

[Possible brute-force / repeated probing]
  Source IP : 198.51.100.12
  Detail    : Triggered "ET SCAN SSH BruteForce" 312 times
```

---

## How it handles large files

Rather than loading the entire log file into memory, the tool reads it line
by line using a generator with an 8MB read buffer. A single pass through the
file collects all the data needed for every command — so even a 700MB log
is processed efficiently without requiring significant RAM.

The `search` command uses its own streaming pass so it can print results
immediately without waiting for the full file to be read.

---

## Suspicious activity detection

Three heuristics are applied automatically:

**Port scan** — a single source IP targeting 10 or more distinct destination
ports is flagged as a possible port scan.

**Brute-force / repeated probing** — a source IP that triggers the same
alert signature 5 or more times is flagged as possible brute-force activity.

**Automated scanner** — a source IP that triggers 5 or more different alert
types is flagged as a possible automated scanner.

Thresholds are set conservatively by default and can be adjusted directly
in the `find_suspicious_activity()` function.

---

## License

This project is licensed under the GNU General Public License v2.0 — see
[LICENSE](./LICENSE) for details.



---