# suReader

EVE Analyzer (suReader) — a small CLI tool to analyze Suricata EVE JSON alert logs and produce human-readable reports for quick incident analysis and SIEM ingestion. Designed as a compact, streaming analyzer for very large Suricata JSON files (no full-file memory load).

Features
- Single-pass streaming analysis (low memory) of Suricata EVE JSON alert logs
- Summaries: top signatures, protocol and port counts, severity breakdown, hourly timeline
- Top IPs report (source / destination)
- Simple heuristics to flag suspicious activity (port scans, repeated signatures, diverse scanners)
- Search mode to filter events by IP or signature keyword
- Exportable text reports into `reports/` folder

Quick start

- Requirements: Python 3.8+ (no external dependencies required)
- Clone the repo and run the CLI from the repository root:

```bash
git clone https://github.com/TheVoidThatConsumes/suReader.git
cd suReader
python main.py summary elogs/<your-eve-file>.json
```

Usage examples
- Summary (overall alert stats)

```bash
python main.py summary elogs/honeypot.json
```

- Top IPs (show top 10 by default)

```bash
python main.py top-ips elogs/conference.json --count 20
```

- Suspicious activity (heuristics)

```bash
python main.py suspicious elogs/honeypot.json
```

- Search for alerts by IP or signature keyword

```bash
python main.py search elogs/honeypot.json --ip 10.0.0.5
python main.py search elogs/honeypot.json --signature "sql injection"
```

- Export a report to `reports/` (auto-named or specify filename)

```bash
python main.py report elogs/honeypot.json --export
python main.py summary elogs/honeypot.json --export my_summary.txt
```

Repository layout
- `main.py`: CLI entrypoint and analyzer implementation
- `elogs/`: example or sample EVE JSON files (this repo already includes two demo files: `honeypot.json` and `conference.json`)
- `reports/`: output folder for exported text reports

Demo files & where to find more
- This repository already contains two small demo EVE JSON files in the `elogs/` folder to try the tool quickly.
- Need more EVE JSON logs? Helpful resources:
	- Suricata EVE JSON format documentation: https://suricata.readthedocs.io/en/latest/output/eve/eve-json-format.html
	- Suricata project homepage: https://suricata.io/
	- Search public repos for `eve.json` on GitHub: https://github.com/search?q=eve.json&type=code

Notes and recommendations
- The tool streams input and tolerates broken/partial JSON lines; it only processes events where `event_type` == `alert`.
- For very large EVE logs the script uses an 8MB read buffer to reduce I/O syscalls and keep memory usage low.
- Thresholds used by the suspicious-activity heuristics are conservative and tunable inside `main.py`.

Contributing
- Suggestions, bug reports and small improvements are welcome. Open an issue or submit a PR.

License
- This repository does not include an explicit license file. If you want to share this code publicly, consider adding a `LICENSE` file.

Author: David Obi
- Personal Cybersecurity portfolio project — 2026

