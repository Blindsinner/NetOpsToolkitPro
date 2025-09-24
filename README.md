
# NetOps Toolkit Pro

> **All-in-one NetOps & Red-Team toolkit** — GUI front end + modular engines for reconnaissance, scanning, phishing simulation, device auditing, blue-team analysis, and more.  
> Built as a developer-first desktop app to centralize workflows commonly used by security testers and network operators.

---

## Table of contents

1. [Purpose & Audience](#purpose--audience)  
2. [High-level Features & Sub-features](#high-level-features--sub-features)  
3. [Quick Start (recommended)](#quick-start-recommended)  
4. [Self-Healing Bootstrap Details](#self-healing-bootstrap-details)  
5. [How to Use — per Feature / Widget / Engine](#how-to-use--per-feature--widget--engine)  
   - Network Ops (GUI)  
   - Red Team — Assess (Naabu, Nuclei, Amass, ZAP, Shodan, Censys, Prowler, Greenbone)  
   - Recon & Fingerprinting  
   - Blue Team & Incident Response  
   - Advanced features (AI assistant, automation, browser automation, honeypots, NAC, password audit)  
   - Phishing Simulator (how to use safely)  
   - Terminals & Device Connectors (SSH, serial, config audit)  
6. [CLI Examples & Example Outputs](#cli-examples--example-outputs)  
7. [Configuration & Persistent Settings (QSettings keys)](#configuration--persistent-settings-qsettings-keys)  
8. [Troubleshooting & FAQs](#troubleshooting--faqs)  
9. [Contributing & Development Guide](#contributing--development-guide)  
10. [License — Use & Modify Only (No Redistribution)](#license)  
11. [Security, Legal & Ethical Notice](#security-legal--ethical-notice)  
12. [Appendix: Useful Commands & Packaging Notes](#appendix-useful-commands--packaging-notes)

---

## Purpose & Audience

**NetOps Toolkit Pro** is a desktop application for:

- **Security testers (red team, bug bounty, pen test):** integrated UI for port scanning, templated vulnerability checks, web scanning, and OSINT lookups.  
- **Network operators / SRE / NetEng:** device inventory, config auditing, SNMP monitoring, troubleshooting utilities.  
- **Blue-teamers:** quick PCAP inspection, log ingestion, offline triage tools.  
- **Developers:** modular, extensible Python + PySide6 project to adapt and extend.

It bundles a Qt GUI, modular engines (some wrap external CLI tools), and utility widgets to speed up lab workflows while remaining scriptable for automation.

---

## High-level features & sub-features

### Network Ops (GUI)
- **Health Dashboard** — multi-device ping/health display.  
- **Diagnostics** — ping/traceroute, netstat, DNS lookups, firewall checks.  
- **Network Scanner** — Nmap/ARP scanner profiles with **tabulated** results.  
- **Adapter Manager** — generate system commands to manage NICs.  
- **Real-time Subnet Calculator, IP Details, Lookups** (WHOIS, GeoIP, DNS).  
- **SSH & Serial Terminals** — interactive terminals with ANSI color handling.  
- **Local Info** — enumerate host interfaces, MACs, vendor lookups.  
- **Topology Visualizer & Config Management** — inventory, backups, diffs.

### Red Team — Assess
- **Naabu** — fast port scanning with streaming results.  
- **Nuclei** — templated vulnerability checks; severity filters, JSONL.  
- **Amass** — passive/active subdomain enumeration.  
- **ZAP** — drive ZAP daemon (spider + active scan) via API.  
- **Shodan & Censys** — API lookups & searches (requires API keys).  
- **Prowler** — cloud (AWS/Azure/GCP) CIS checks.  
- **Greenbone/OpenVAS** — manage tasks and fetch results (GVM).  
- **Scanner chaining** — run **Naabu → Nuclei** automatically.

### Recon & Fingerprinting
- **JS Recon**, **Header Analyzer**, **Wappalyzer** tech detection.  
- **Wayback / Screenshot** helpers (if present/available).  
- **Directory Bruteforcer** — wordlists, status filters.

### Blue Team & Incident Response
- **PCAP Inspector** (Scapy summaries & reports).  
- **Log Analyzer & Ingestor** — counts, heuristics, CSV/JSON export.  
- **Incident Response** — live capture (Scapy) & triage helpers.  
- **Honeypot Manager** — lightweight listeners & event view.

### Advanced Features
- **AI Assistant** — OpenAI / Gemini / Ollama adapters.  
- **Automation & Playbooks** — device automation (YAML).  
- **Browser Automation** — QtWebEngine-backed flows (fallbacks supported).  
- **Crypto Tools** — hashing, Fernet, enc/dec helpers.  
- **Performance Monitoring** — SNMP collectors; **NAC UI**.  
- **Password Auditor** — defensive audit tools.

### Phishing Simulator
- Compose HTML emails, CSV recipients, SMTP send, save `.eml`, attachments, optional tracking pixel.  
- Full controls for sender identity, envelope, SMTP settings.

### Packaging / Helpers
- **PyInstaller hook** for `networkx` (`hook-networkx.py`) if you build frozen binaries.  
- **Task manager + logger** for async jobs and streaming outputs.

---

## Quick Start (recommended)

These commands assume a Debian/Kali-style system and Python 3 installed.

1) **Clone the project**
```bash
git clone <your-repo> netops-toolkit-pro
cd netops-toolkit-pro
````

2. **Start the bootstrap + GUI**

```bash
python3 main.py
```

`main.py` will:

* create `.venv-netops-toolkit` if needed,
* install Python dependencies into that venv,
* on Debian/Kali: attempt to install common external tools via `apt`,
* optionally start `zap.sh` in daemon mode (if ZAP present),
* re-exec into the created venv and launch the Qt GUI.

3. **Set API keys** in **Settings** (Shodan, Censys, ZAP API key, Vulners, HIBP) and scanner defaults.

---

## Self-Healing Bootstrap Details

**No `requirements.txt` needed.** Running `python3 main.py`:

* Creates/reuses a dedicated virtualenv: `.venv-netops-toolkit`.
* Upgrades pip and installs Python packages (PySide6, httpx\[http2], dnspython, scapy, netmiko, pysnmp, qasync, python-whois, psutil, pyserial, pyyaml, networkx, python-wappalyzer, python-nmap, yara-python, pandas, easysnmp, …).
* On Debian/Kali, attempts `apt-get install` of common CLI tools (e.g., `zaproxy`, `naabu`, `nuclei`, `amass`, `gvm`, `gvm-tools`, `python3-gvm`, `nmap`, `nikto`, `hydra`, `exploitdb`, `jq`, `curl`, and build deps `libsnmp-dev`, `swig`, `build-essential`, `python3-dev`).
* Uses **pipx** for select tools (e.g., `prowler`) when appropriate.
* Seeds resources (e.g., clones `nuclei-templates` into `.bootstrap` if needed).
* Tries to start ZAP in daemon mode (non-fatal if not ready yet).
* Re-launches the app **inside** the venv and opens the GUI.

If something fails (e.g., a tool not available on your OS), the bootstrap **logs and continues**. You can always install missing bits manually and rerun.

---

## How to Use — per Feature / Widget / Engine

> Any widget that wraps a CLI (Naabu, Nuclei, Amass, ZAP, Prowler) expects the binary in your `PATH`. API-based features require valid keys in Settings.

### Network Ops (GUI)

**Health Dashboard**

* *Purpose:* reachability & latency overview.
* *Use:* add devices in config → open dashboard → live status and color-coded health.

**Diagnostics**

* *Purpose:* ping, traceroute, DNS, netstat.
* *Use:* select target/IP → run checks → copy report.

**Network Scanner**

* *Purpose:* Nmap/ARP scans with **tabulated** results.
* *Use:* choose profile (fast/full), target (IP/CIDR) → start scan → review open ports & banners.

**Adapters / Local Info / IP Details**

* *Purpose:* NIC helpers, interface info, subnet math.
* *Use:* open widget → run actions or copy suggested commands (root may be required for system changes).

**SSH & Serial Terminals**

* *Purpose:* interactive access.
* *Use:* SSH: host/user/key/password → Connect. Serial: pick port & baud → Connect.

---

### Red Team — Assess

**Naabu (fast port scan)**

* *Use case:* quick TCP/UDP port enumeration.
* *Use:* set target + ports/rate → Run; output streams as `ip:port`.

**Nuclei (templated vuln scan)**

* *Use case:* run PD templates.
* *Use:* set templates path (e.g., `.bootstrap/nuclei-templates`), target or feed from Naabu → choose severities → Run.
* *Output:* template id, host, matched evidence (JSONL optional).

**Amass (subdomain enumeration)**

* *Use case:* passive/active subdomain discovery.
* *Use:* set domain + mode → Run → parse results in tab.

**ZAP (DAST via API)**

* *Use case:* spider + active scan.
* *Use:* ensure ZAP present; if needed start:
  `zap.sh -daemon -port 8090 -config api.key=<key>`
  set ZAP host/port/key in Settings → in the ZAP tab enter URL → Spider/Active Scan.
* *Note:* first spider can be slow; app streams progress.

**Shodan & Censys**

* *Use case:* internet telemetry.
* *Use:* set API keys in Settings → host lookup or search queries → inspect banners/certs/metadata.

**Prowler (cloud checks)**

* *Use case:* CIS & security posture.
* *Use:* set AWS profile/regions in Settings or `~/.aws/credentials` → Run → review pass/fail findings.

**Greenbone / OpenVAS (GVM)**

* *Use case:* authenticated vulnerability scanning at scale.
* *Use:* ensure GVM up → set host/port/user/pass → list/create tasks, get results.

**Chaining: Naabu → Nuclei**

* *Flow:* run Naabu → feed discovered hosts/ports into Nuclei templates automatically.

---

### Recon & Fingerprinting

**Header Analyzer**

* *Purpose:* inspect CSP, HSTS, X-Frame, cookies.
* *Use:* paste URL → Analyze → see missing/misconfigured headers + suggested fixes.

**JS Recon / Wappalyzer**

* *Purpose:* endpoints, framework fingerprints.
* *Use:* point at URL → collect libraries/versions and interesting JS references.

**Directory Bruteforcer**

* *Purpose:* find hidden endpoints.
* *Use:* set URL + wordlist + threads + status filters → Run → review hits.

---

### Blue Team & Incident Response

**PCAP Inspector**

* *Purpose:* summarize PCAPs, surface anomalies.
* *Use:* open `.pcap` → see top talkers/protocols/suspicious flows → extract sessions.

**Log Analyzer & Ingestor**

* *Purpose:* parse syslog/app logs.
* *Use:* load or tail logs → run heuristics → export CSV/JSON.

**Incident Response**

* *Purpose:* live packet capture and quick triage.
* *Use:* start capture (Scapy), stop/save `.pcap`, analyze.

**Honeypot Manager**

* *Purpose:* simple listeners for detection/telemetry.
* *Use:* choose protocol/port → start → view events.

---

### Advanced Features

**AI Assistant**

* *Purpose:* in-app help, code, analysis.
* *Use:* configure OpenAI / Gemini / Ollama in Settings → chat in the widget.

**Automation & Playbooks**

* *Purpose:* repeatable device workflows.
* *Use:* write YAML playbook → test single device → run multi-target with confirmations.

**Browser Automation**

* *Purpose:* scripted web checks/previews.
* *Use:* run flow scripts; QtWebEngine if available, fallback otherwise.

**Crypto Tools**

* *Purpose:* hashing/encoding/encryption helpers.

---

### Phishing Simulator (IMPORTANT)

**Purpose**: authorized training & simulations **only**.

**Use**

1. Open Phishing Simulator (Advanced).
2. Pick **Manual** or **CSV** recipients (`to`, `cc`, `bcc` columns; case-insensitive).
3. Set SMTP host/port/user/pass, tick the confirmation box.
4. Compose HTML (or load template), preview, **send** or **Save .eml** for offline tests.

**Notes**

* Tracker pixel is optional; labs only.
* SPF/DKIM/DMARC affect deliverability (see `Phishing_Simulation_user_guide.html`).
* For safe testing, use a local SMTP test server (MailHog, smtp4dev) or an isolated lab mail server.

---

## CLI Examples & Example Outputs

**Naabu**

```bash
naabu -host example.com -ports top-1000 -o naabu-out.txt
```

Example:

```
93.184.216.34:80
93.184.216.34:443
93.184.216.34:8080
```

**Nuclei**

```bash
nuclei -t ~/.local/share/nuclei-templates/ -u https://example.com -severity critical,high -o nuclei.jsonl -json
```

Example JSONL:

```json
{"template-id":"cves/2024-xxxx","severity":"high","matched":"CVE-2024-xxxx","host":"https://example.com"}
```

**Amass**

```bash
amass enum -d example.com -o amass-out.txt
```

Example:

```
dev.example.com
api.example.com
admin.example.com
```

**ZAP (daemon)**

```bash
zap.sh -daemon -port 8090 -config api.key=<key>
```

Example alert:

```
- Alert: Cross-Site Scripting (Reflected)
  Risk: High
  URL: https://example.com/search?q=<script>
  Evidence: <script> echoed in response
```

**Prowler**

```bash
prowler -p default -R us-east-1
```

Example:

```
[PASS] 1.1  MFA enabled for all IAM users with console password
[FAIL] 2.3  S3 bucket allows public read
```

**PCAP Inspector**

```
Summary:
- Packets: 12,345
- Top talker: 10.0.0.5 (1,234 pkts)
- Protocols: TCP(78%), UDP(15%), ICMP(7%)
- Possible exfil: 10.0.0.5 → 198.51.100.25 (80 large payloads)
```

---

## Configuration & Persistent Settings (QSettings keys)

* `security/vulners_api_key` — Vulners API key
* `security/hibp_api_key` — HaveIBeenPwned API key
* `security/shodan_api_key` — Shodan API key
* `security/censys_api_id`, `security/censys_api_secret` — Censys credentials
* `security/zap_api_key` — ZAP API key
* `scanner/nuclei_templates_path` — path to `nuclei-templates` (default: `.bootstrap/nuclei-templates`)
* `scanner/naabu_ports`, `scanner/naabu_rate` — Naabu defaults
* `scanner/nuclei_severity` — Nuclei severity defaults
* `scanner/amass_config_path` — optional Amass config
* `cloud/aws_profile`, `cloud/aws_access_key_id`, `cloud/aws_secret_access_key`, `cloud/aws_region` — for cloud checks (Prowler)
* `gvm/host`, `gvm/port`, `gvm/user`, `gvm/pass` — Greenbone/GVM settings

---

## Troubleshooting & FAQs

**ZAP API not reachable**
Start ZAP manually:

```bash
zap.sh -daemon -port 8090 -config api.key=<key>
```

Match host/port/key in Settings.

**Nuclei templates missing**

```bash
mkdir -p .bootstrap
git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git ./.bootstrap/nuclei-templates
```

Then set `scanner/nuclei_templates_path` in Settings.

**Native deps missing for Python packages (easysnmp, etc.)**

```bash
sudo apt-get install libsnmp-dev swig build-essential python3-dev
```

Re-run `python3 main.py`.

**SSH/Serial connection issues**

* Serial: ensure permission for `/dev/tty*` (add user to `dialout`).
* SSH: verify host reachability, creds, and key permissions.

**A tool binary not found (naabu/nuclei/amass/prowler)**
Install via `apt` or upstream release, ensure it’s in `PATH`, then rerun.

---

## Contributing & Development Guide

Contributions are welcome:

1. Fork → branch → PR.
2. Keep UI widgets in `app/widgets`, engines in `app/core`, assess engines in `app/core/assess`.
3. Avoid blocking the UI thread: use the Task Manager or subprocess with streamed output.
4. Catch `FileNotFoundError` for external binaries and show actionable messages.
5. Provide repro steps in PRs; add small tests where meaningful.

If you’d like, open an issue to discuss larger changes before implementation.

---

## License

**Custom License — Use & Modify Only (No Redistribution)**

* ✅ You may **use** and **modify** this project for personal, internal, research, or client work.
* ❌ You may **not distribute** the original or modified versions publicly or to third parties outside your organization, in whole or in part, without explicit written permission from the owner/author.

For commercial or redistribution requests, contact the repository owner to discuss licensing (e.g., MIT/Apache/GPL) and terms.

> This does **not** supersede licenses of third-party tools/templates (e.g., `nuclei-templates`, `gvm`, `zaproxy`). Respect their licenses when bundling or distributing.

---

## Security, Legal & Ethical Notice

This toolkit contains capabilities that can be intrusive or illegal if used improperly (scanning, brute forcing, spoofed email, vulnerability exploitation). Use **only** on systems you own or have **explicit, written authorization** to test. Unauthorized testing is illegal in most jurisdictions.

Phishing simulations must be approved and confined to controlled environments.

---

## Appendix: Useful Commands & Packaging Notes

**Quick commands**

```bash
# start the app
python3 main.py

# activate venv manually (optional)
source .venv-netops-toolkit/bin/activate

# clone nuclei templates (if missing)
mkdir -p .bootstrap
git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git ./.bootstrap/nuclei-templates

# start ZAP manually
zap.sh -daemon -port 8090 -config api.key=$(python3 - <<'PY'
import secrets; print(secrets.token_hex(32))
PY
)

# run naabu manually
naabu -host example.com -ports top-1000 -o naabu-results.txt

# run nuclei manually
nuclei -t ~/.local/share/nuclei-templates/ -u https://example.com -o nuclei-out.txt
```

**Packaging with PyInstaller**

* Keep `hook-networkx.py` to ensure `networkx` data is collected.
* For cross-platform binaries, bundle native libs and document external CLI tools as system requirements.

```
::contentReference[oaicite:0]{index=0}
```
