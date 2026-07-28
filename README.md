# TWReconHunter

TWReconHunter is a passive reconnaissance tool written in Go for authorized security testing, bug bounty research, and web application assessment workflows.

It is designed to help security researchers quickly gather reconnaissance data, identify low-severity configuration issues, and prioritize manual review for high-value targets. The project focuses on a safe, passive workflow and is intended for authorized testing only.

## Why this project exists

Security teams and bug bounty hunters often need a fast way to:

- understand a target domain and its exposed surface
- collect passive recon hints from public sources
- identify common security misconfigurations
- prioritize interesting endpoints for manual review
- export results into structured report formats

TWReconHunter aims to support that workflow with a lightweight CLI tool that is easy to install and run on Linux systems.

## Key features

- passive recon for target URLs and domains
- scope confirmation workflow before scanning
- basic subdomain discovery hints
- HTTP response and header-based checks
- passive detection of common security header issues
- P1-to-P5 manual review triage suggestions
- JSON and HTML report export for documentation and follow-up review

## Installation

### Clone and build from source

```bash
git clone https://github.com/tawhid2005/TWReconHunter.git
cd TWReconHunter/go-reconhunter
go mod tidy
go build .
```

### Linux install from GitHub

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

## Example output

```text
Target: https://example.com
Status: 200

[Subdomains]
- No subdomains discovered from passive sources

[Findings]
[MEDIUM] Missing strict-transport-security
[MEDIUM] Missing content-security-policy
```

## Project structure

- main.go - CLI entry point and command handling
- scanner.go - passive scan and recon logic
- triage.go - P1-to-P5 manual review scoring
- report.go - JSON and HTML report export
- main_test.go - basic regression tests

## Safety and ethics

TWReconHunter is intentionally passive. It does not send exploit payloads or perform active exploitation. It is meant for authorized testing only and should be used responsibly.

## License

This project is licensed under the MIT License.
