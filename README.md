Perfect. I’ll generate a **GUI-only README.md** for your ZIP project — no CLI examples, only **GUI workflows, screenshots placeholders, expected outputs**.

Here’s the corrected file in Markdown:


# NetOps Toolkit Pro

> **All-in-one NetOps & Red-Team toolkit** — GUI front end + modular engines for reconnaissance, scanning, phishing simulation, device auditing, blue-team analysis, and more.  
> Designed for security testers, red teams, network operators, and blue teams who prefer an integrated desktop interface.

---

## Table of contents

1. [Purpose & Audience](#purpose--audience)  
2. [Features & Sub-features](#features--sub-features)  
3. [Quick Start](#quick-start)  
4. [Self-Healing Bootstrap](#self-healing-bootstrap)  
5. [How to Use — per Widget](#how-to-use--per-widget)  
   - Network Ops  
   - Red Team — Assess  
   - Recon & Fingerprinting  
   - Blue Team & IR  
   - Advanced Features  
   - Phishing Simulator  
   - Terminals & Device Connectors  
6. [Configuration & Settings](#configuration--settings)  
7. [Troubleshooting](#troubleshooting)  
8. [Contributing](#contributing)  
9. [License](#license)  
10. [Security Notice](#security-notice)

---

## Purpose & Audience

**NetOps Toolkit Pro** is a desktop GUI application for:

- **Security testers / red team** → scanning, recon, vuln checks, phishing simulation.  
- **Network engineers / operators** → inventory, config management, monitoring, troubleshooting.  
- **Blue-teamers** → PCAP inspection, log analysis, honeypots, incident response.  
- **Developers** → extendable PySide6 project with modular engines and widgets.

---

## Features & Sub-features

### Network Ops
- **Health Dashboard** → device reachability/latency.  
- **Diagnostics** → ping, traceroute, DNS, firewall checks.  
- **Network Scanner** → tabulated scan results (open ports, services).  
- **Adapter Manager** → generate/manage NIC commands.  
- **Subnet Calculator & IP Details** → instant subnet/IP math.  
- **Local Info** → enumerate interfaces, MAC, vendor.  
- **Topology Visualizer** → network maps, config backups/diffs.  
- **SSH & Serial Terminals** → embedded terminals inside the GUI.

### Red Team — Assess
- **Naabu** → fast port scanning, results streamed into GUI table.  
- **Nuclei** → templated vulnerability checks (severity filters, JSON).  
- **Amass** → passive/active subdomain discovery.  
- **ZAP** → spidering & active scans (ZAP daemon controlled in background).  
- **Shodan & Censys** → API search/lookup in the GUI.  
- **Prowler** → AWS compliance scans (results in GUI).  
- **Greenbone/OpenVAS** → manage GVM tasks and view results.  
- **Scan chaining** → e.g. feed Naabu → Nuclei seamlessly.

### Recon & Fingerprinting
- **Header Analyzer** → inspect CSP, HSTS, X-Frame, cookies.  
- **JS Recon** → extract endpoints from JS.  
- **Wappalyzer engine** → fingerprint frameworks & libs.  
- **Directory Bruteforcer** → find hidden endpoints with wordlists.

### Blue Team & Incident Response
- **PCAP Inspector** → upload PCAP, see summaries, flows, anomalies.  
- **Log Analyzer & Ingestor** → ingest log files, flag anomalies, export reports.  
- **Incident Response Widget** → capture packets live (save as PCAP).  
- **Honeypot Manager** → deploy listeners, collect connection logs.

### Advanced Features
- **AI Assistant** → ask questions, generate snippets, explain findings (supports OpenAI, Gemini, Ollama).  
- **Automation & Playbooks** → YAML playbooks for devices.  
- **Browser Automation** → drive test flows (QtWebEngine).  
- **Crypto Tools** → hashing, encrypt/decrypt, key generation.  
- **Performance Monitoring & NAC** → SNMP monitors, network access control.  
- **Password Auditor** → test passwords securely in audits.

### Phishing Simulator
- **Compose & send emails** → HTML or templates.  
- **Recipient management** → manual entry or CSV import (`to`, `cc`, `bcc`).  
- **SMTP settings** → host, port, auth, TLS.  
- **Extras** → tracking pixel, save `.eml` files, attachments.  
- **Preview mode** → check layout before sending.  
⚠️ Use only in labs or with explicit authorization.

---

## Quick Start

1. Clone the repo and open folder:
   ```
   git clone https://github.com/Blindsinner/NetOpsToolkitPro
   cd NetOpsToolkitPro


3. Run the application:

   ```
   python3 main.py

3. The GUI will launch after bootstrap.

4. Use the **Settings widget** to configure:

   * Shodan / Censys API keys
   * ZAP API key + host/port
   * AWS credentials (for Prowler)
   * Vulners, HIBP keys (optional)

---

## Self-Healing Bootstrap

No `requirements.txt` needed.

* `main.py` **creates `.venv-netops-toolkit`**, upgrades pip, installs Python dependencies.
* On **Debian/Kali**, it installs missing tools (`zaproxy`, `naabu`, `nuclei`, `amass`, `nmap`, `nikto`, `hydra`, `gvm`, `gvm-tools`, `prowler` via pipx).
* If a tool is missing, the GUI **still loads** — unavailable features are just disabled until installed.
* Automatically attempts to launch **ZAP daemon** with API key.

---

## How to Use — per Widget

### Network Ops

* Open **Network Ops tab** → select Health Dashboard, Scanner, Diagnostics.
* Results are shown in **tables or text panels** inside the GUI.

### Red Team — Assess

* Open **Assess tab**.
* Choose engine (Naabu, Nuclei, Amass, etc.).
* Enter target, set options, click **Run**.
* Results stream into the widget with tables/logs.

### Recon

* Open **Recon widgets**.
* Paste URL/domain → click Analyze.
* Results show headers, tech stack, or directory results.

### Blue Team

* Upload a PCAP in **PCAP Inspector** → summary tables + charts.
* Load logs in **Log Analyzer** → flagged anomalies in table view.
* Use **Incident Response** for live captures.

### Advanced

* **AI Assistant**: chat window inside GUI.
* **Playbooks**: load YAML, select device(s), run.
* **Crypto tools**: enter text → hash/encrypt/decrypt in widget.
* **Performance Monitor**: SNMP data updates charts.

### Phishing Simulator

* Open **Phishing Simulator widget**.
* Fill SMTP + recipients.
* Compose email (HTML editor provided).
* Preview → Send or Save `.eml`.

---

## Configuration & Settings

All settings are stored with **Qt QSettings**, persistent across runs.
Key categories:

* `security/` → API keys (Shodan, Censys, Vulners, HIBP, ZAP)
* `scanner/` → Nuclei templates path, Naabu defaults, etc.
* `cloud/` → AWS creds & region
* `gvm/` → Greenbone host, port, user, pass

Edit them via **Settings widget**.

---

## Troubleshooting

* **Missing tool** → Install it (`naabu`, `nuclei`, `amass`, etc.) and restart.
* **ZAP not reachable** → Start manually: `zap.sh -daemon -port 8090 -config api.key=<yourkey>`
* **SNMP errors** → Install native libs: `sudo apt install libsnmp-dev swig build-essential python3-dev`
* **Serial errors** → Add your user to `dialout` group.

---

## Contributing

* Fork → Branch → PR.
* Keep UI widgets in `app/widgets`, engines in `app/core`.
* Avoid blocking UI thread (use TaskManager).
* Add error handling if external tools are missing.

---

## License

**Custom — Use & Modify Only, No Redistribution**

* ✅ Allowed: use, run, modify for personal, research, internal, or client work.
* ❌ Not allowed: redistribute, publish, sublicense, or sell without written permission.

Third-party tools (Naabu, Nuclei, ZAP, etc.) remain under their original licenses.

---

## Security Notice

This GUI contains offensive & defensive tools: scanning, brute forcing, phishing simulation.

* **Use only with explicit authorization.**
* **Phishing Simulator:** training/lab environments only.
* Misuse can be **illegal** and is your responsibility.

---

```

Would you like me to also **add screenshot placeholders** (like `![screenshot](assets/screenshots/dashboard.png)`) in each section, so your README looks polished when you publish it?
```
