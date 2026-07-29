<h1 align="center">
  <br>
  <a href="https://github.com/tawhid2005/TWReconHunter"><img src="https://img.shields.io/badge/TWReconHunter-Bug%20Bounty%20Recon%20Tool-red.svg?style=for-the-badge" alt="TWReconHunter"></a>
  <br>
  TWReconHunter
  <br>
</h1>

<h4 align="center">An Advanced, Lightning-Fast Bug Bounty Reconnaissance and Fuzzing Tool built in Go & Python.</h4>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#tui-interactive-mode-go-only">TUI Dashboard</a> •
  <a href="#disclaimer">Disclaimer</a>
</p>

---

## 🔍 What is TWReconHunter?
**TWReconHunter** is a next-generation Bug Bounty reconnaissance tool designed for ethical hackers, penetration testers, and cybersecurity researchers. It combines **Passive Enumeration** and **Active Fuzzing** to discover hidden endpoints, JavaScript files, secret leaks (API keys/tokens), and subdomain takeovers. 

Available in both **Go (compiled, blazingly fast)** and **Python 3 (asyncio-powered)**, this tool is built to maximize your attack surface mapping while staying stealthy.

## 🚀 Key Features

* **Advanced Web Crawler (Spidering):** Automatically crawls targeted links up to depth 2 to map out the entire application attack surface.
* **Deep JavaScript Analysis (JS Mining):** Extracts undocumented API routes and high-priority secrets (AWS Keys, GitHub Tokens, Stripe APIs, RSA Keys) directly from hidden `.js` files.
* **Subdomain Takeover Scanner:** Actively scans discovered subdomains against known cloud provider error signatures (AWS S3, GitHub Pages, Heroku, etc.).
* **Targeted Directory Fuzzing:** Rapidly checks for exposed sensitive files (`.env`, `.git/config`, `swagger.json`).
* **Hidden Parameter Fuzzing:** Automatically appends common parameters (`?admin=1`, `?debug=true`) to high-value endpoints and analyzes response length differences to uncover hidden functionalities.
* **Interactive TUI Dashboard (Go):** A beautiful Terminal User Interface (TUI) for interactive reconnaissance and targeted fuzzing using arrow keys.
* **Instant Webhook Alerts:** Built-in Discord and Telegram webhook support to instantly notify you on your mobile device when a **P1/P2 Severity Bug** is found!

## ⚙️ Installation

### 1. The Go Version (Recommended for Speed & TUI)
You need to have [Go](https://golang.org/doc/install) installed.
```bash
git clone https://github.com/tawhid2005/TWReconHunter.git
cd TWReconHunter/go-reconhunter
go mod tidy
go build -o twreconhunter.exe
```

### 2. The Python Version (Asyncio Powered)
You need to have Python 3 and `aiohttp` installed.
```bash
git clone https://github.com/tawhid2005/TWReconHunter.git
cd TWReconHunter
pip install aiohttp
```

## 🛠️ Usage

### Go Usage
```bash
# Passive Recon with Deep Spidering & JS Mining
./twreconhunter.exe -u https://example.com --confirm-scope --deep

# Active Recon with Directory & Parameter Fuzzing
./twreconhunter.exe active -u https://example.com --confirm-scope

# Passive Recon + Discord Webhook Alerts
./twreconhunter.exe -u https://example.com --confirm-scope --deep --discord "YOUR_WEBHOOK_URL"
```

### TUI Interactive Mode (Go Only)
Want a visual dashboard? Use the interactive mode!
```bash
./twreconhunter.exe interactive -u https://example.com --confirm-scope --deep
```
*(Navigate with Tab/Arrow Keys. Press Enter on an endpoint to run targeted active fuzzing!)*

### Python Usage
```bash
# Async Passive + Active Scan with Spidering
python twreconhunter.py -u https://example.com --confirm-scope --deep --active
```

## 📊 Report Generation
The Go version natively supports generating beautiful HTML and JSON reports for Bug Bounty submissions:
```bash
./twreconhunter.exe -u https://example.com --confirm-scope --output-html report.html --output-json report.json
```

## ⚠️ Disclaimer
**TWReconHunter** is developed for **educational and authorized testing purposes only**. Always ensure you have explicit permission (e.g., a Bug Bounty program brief) before scanning a target. The developers are not responsible for any misuse or damage caused by this tool.

---
<p align="center">
  <i>Developed with ❤️ for the Cybersecurity & Bug Bounty Community.</i>
</p>
