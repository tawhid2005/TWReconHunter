# TWReconHunter

TWReconHunter is a passive reconnaissance and manual review assistant written in Go for authorized security testing, bug bounty research, and recon workflows.

It helps an operator quickly understand a target by gathering:

- a basic target overview
- passive subdomain discovery hints
- security header and configuration findings
- endpoint categories for manual review
- P1-to-P5 style triage suggestions for follow-up testing

## Important safety note

This tool is intentionally passive. It does not send exploit payloads or perform active vulnerability exploitation. It is meant for authorized testing only.

## Features

- Cobra-based CLI
- URL input with scope confirmation flag
- passive HTTP probing
- passive subdomain discovery hints
- security header and config-based findings
- manual triage output from P1 to P5
- JSON and HTML report export

## Installation

```bash
git clone https://github.com/tawhid2005/TWReconHunter.git
cd TWReconHunter/go-reconhunter
go mod tidy
```

## Linux install from GitHub

```bash
chmod +x install.sh
./install.sh
```

## Usage

```bash
twreconhunter -h
twreconhunter -u https://example.com --confirm-scope
twreconhunter -u https://example.com --confirm-scope --output-json reports/example.json --output-html reports/example.html
twreconhunter update
```

## Help and examples

```bash
twreconhunter --help
twreconhunter update --help
```

## Example output

```text
Target: https://example.com
Status: 200

[Subdomains]
- No subdomains discovered from passive sources

[Findings]
[MEDIUM] Missing strict-transport-security - The response does not include strict-transport-security.
[MEDIUM] Missing content-security-policy - The response does not include content-security-policy.
```

## Project structure

- main.go - CLI entry point and command handling
- scanner.go - passive scan and recon logic
- triage.go - P1-to-P5 manual review scoring
- report.go - JSON and HTML report export
- main_test.go - basic regression tests

## License

This project is licensed under the MIT License.
