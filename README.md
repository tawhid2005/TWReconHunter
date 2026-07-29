# TWReconHunter

TWReconHunter is a lightweight Go-based recon and triage tool for authorized security testing, bug bounty research, and web application review.

It is designed to help researchers quickly gather reconnaissance clues, identify interesting surfaces, and prioritize likely bug bounty targets without turning into an exploit framework.

## Why this project exists

Security researchers often need a fast and professional workflow to:

- understand a target domain and its exposed surface
- discover likely links, parameters, and subdomain hints
- identify common security misconfigurations
- prioritize interesting endpoints for manual review
- export structured reports for documentation and handoff

TWReconHunter aims to support that workflow with a simple CLI that is easy to install and run.

## Key features

- passive recon for target URLs and domains
- one-command active-style recon workflow via the active subcommand
- link and parameter discovery from a starting URL
- candidate scoring for admin, login, upload, API, and sensitive paths
- optional research header support for authorized testing
- JSON and HTML report export
- P1-to-P5 style triage suggestions for manual review

## Installation

### Clone the repository

```bash
git clone https://github.com/tawhid2005/TWReconHunter.git
cd TWReconHunter
```

### Build from source

```bash
cd go-reconhunter
go mod tidy
go build -o twreconhunter .
```

### Linux install helper

```bash
chmod +x install.sh
./install.sh
```

If the command is not found after installation, add the local bin directory to your shell startup file:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Then run:

```bash
twreconhunter -h
twreconhunter active -u https://example.com --confirm-scope
```

## Usage

### One-command recon workflow

This is the recommended starting point for a fast recon and triage run.

```bash
twreconhunter active -u https://example.com --confirm-scope
```

### Passive scan

```bash
twreconhunter -u https://example.com --confirm-scope
```

### Scan with an optional research header

Use this only for authorized testing when you want to identify your research context in outbound requests.

```bash
twreconhunter -u https://example.com --confirm-scope --research-header your-h1-username
```

### Deep passive review

```bash
twreconhunter -u https://example.com --confirm-scope --deep
```

### Export reports

```bash
twreconhunter -u https://example.com --confirm-scope --output-json reports/example.json --output-html reports/example.html
```

### Update the installed binary

```bash
twreconhunter update
```

## What the tool reports

When you run a scan, TWReconHunter can show:

- the starting target URL and status
- discovered links and parameters
- likely subdomain hints
- candidate paths that look like high-value bug bounty surfaces
- triage suggestions such as admin, login, upload, or API review areas
- optional JSON and HTML reports for documentation

## Example output

```text
Warning: this active mode sends test requests and should only be used on authorized targets.
Active scan results for https://example.com
Discovered links: 2
Parameters:
No findings from the initial active checks
```

## Project structure

- main.go - CLI entry point and command handling
- scanner.go - passive scan and recon logic
- triage.go - P1-to-P5 manual review scoring
- report.go - JSON and HTML report export
- active.go - active-style recon workflow and candidate scoring
- main_test.go - regression tests

## Safety and ethics

TWReconHunter is intentionally passive by default and uses a lightweight active-style workflow only for safe reconnaissance and review guidance. It does not send exploit payloads or perform destructive actions. It is meant for authorized testing only and should be used responsibly.

## License

This project is licensed under the MIT License.
