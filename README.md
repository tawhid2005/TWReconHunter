# TWReconHunter

TWReconHunter is a passive reconnaissance prototype written in Go for authorized security testing and bug bounty workflows.

It is designed to help an operator quickly understand a target by gathering:

- a basic target overview
- subdomain discovery from passive certificate sources
- passive findings such as missing security headers
- endpoint categories for manual review

## Important safety note

This tool is intentionally passive. It does not send exploit payloads or perform active vulnerability exploitation. It is meant for authorized testing only.

## Features

- Cobra-based CLI
- URL input with scope confirmation flag
- passive HTTP probing
- subdomain discovery through public certificate data
- structured findings for manual review

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

- main.go - CLI entry point
- scanner.go - passive scan and recon logic
- main_test.go - basic regression tests

## License

This project is licensed under the MIT License.
