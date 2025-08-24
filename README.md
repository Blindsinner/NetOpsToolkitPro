
---
# NetOpsToolkitPro

> **All-in-one Swiss-army toolkit for Network Operations & Security**  
> Reconnaissance • Red-Team • Blue-Team • Automation • Compliance • AI Copilot  

---

## 🎯 Purpose

NetOpsToolkitPro consolidates red-team, blue-team, and NetOps utilities into a single **self-healing, GUI-driven application**.  
It removes the pain of juggling multiple scripts and command-line tools by offering a modular dashboard with widgets for each feature.

Ideal for:
- **Network & Security Engineers** who need a one-stop operational console.  
- **Purple-Team exercises** where red and blue roles collaborate in one tool.  
- **Students & Trainers** for labs, workshops, and CTFs.  

---

## 🚀 Features Overview

- **Reconnaissance Suite**: subdomain scanning, header analysis, JS analyzer, screenshot grabber.  
- **Phishing Simulator** with HTML templates.  
- **Password Auditor** for hash strength testing.  
- **Directory Bruteforcer** for hidden endpoints.  
- **Incident Response Playbooks** and log triage.  
- **Honeypot Manager** to trap attackers.  
- **Network Access Control (NAC)** for rogue device detection.  
- **Config Manager** for device backups and diffs.  
- **Cloud Dashboard** (AWS/Azure/GCP).  
- **Performance Monitoring**.  
- **AI Copilot**: conversational log and findings analysis.  
- **Future Modules**: Playbooks automation (SOAR-lite), Compliance Checker, Container Launcher, Topology Mapper.  

---

## 🛠️ Installation

The toolkit is **self-healing** — no manual dependency installs.  
Requires only **Python 3.11+** (present on Kali Linux).

### On Kali Linux

```bash
# Clone the repository
git clone https://github.com/Blindsinner/NetOpsToolkitPro.git
cd NetOpsToolkitPro

# Run the app (first run takes a few minutes)
sudo python3 main.py
````

* First launch:

  * Creates `.venv-netops-toolkit/`.
  * Installs dependencies.
  * Opens GUI dashboard.

* Subsequent runs:

  ```bash
  sudo python3 main.py
  ```

---

## ⚙️ Configuration

- **Device configs**: `device_configs/devices.json` and backups.  
- **Assets**: icons, phishing templates in `assets/`.  
- **Logs**: `netops_toolkit.log` and `user_activity.log` in root.  
- **API keys**: managed directly in the **Settings panel** inside the GUI.  
  - Currently supported: VirusTotal, AbuseIPDB, OTX.  
  - Enter your keys once and they are saved for future sessions.  


  ```bash
  export VT_API_KEY="your_vt_key"
  export ABUSEIPDB_KEY="your_abuse_key"
  ```

---

## 📖 Full User Guide

This section walks through **every major tool**, its purpose, how to launch it in the GUI, and typical usage.

---

### 🔍 Reconnaissance Suite

**Location:** `app/advanced_features/recon_*`, `app/core/recon/`

#### Subdomain Scanner

* Purpose: Discover subdomains of a given domain.
* Launch: **Advanced Features → Recon → Subdomains**.
* Input: target domain, optional wordlist (`subdomains.txt`).
* Output: Table of subdomains, exportable JSON/CSV.

#### Header Analyzer

* Purpose: Inspect HTTP headers for missing security settings.
* Launch: **Advanced Features → Recon → Header Analyzer**.
* Input: URL.
* Output: List of headers, flags missing items (e.g., CSP, HSTS).

#### JavaScript Analyzer

* Purpose: Find endpoints, secrets, or links inside JS files.
* Launch: **Advanced Features → Recon → JS Analyzer**.
* Input: URL or file.
* Output: Extracted endpoints, highlighted risky strings.

#### Screenshot Grabber

* Purpose: Visual recon of targets.
* Launch: **Advanced Features → Recon → Screenshot Tool**.
* Input: URL.
* Output: Screenshot PNG preview + export.

---

### 🎭 Phishing Simulator

**Location:** `app/phishing_simulator_widget.py`, `app/core/phex/templates/`

* Purpose: Run **lab-safe phishing simulations**.
* Templates: Office365, Google Workspace, Microsoft 365, Okta.
* Launch: **Phishing Simulator Widget**.
* Steps:

  1. Choose template.
  2. Add recipients (lab/testing only).
  3. Send.
  4. Track opens/clicks in logs.

⚠️ **Important:** For training labs only. Unauthorized phishing is illegal.

---

### 🔑 Password Auditor

**Location:** `app/advanced_features/password_audit_widget.py`, `app/core/password_auditor_engine.py`

* Purpose: Check password strength via cracking tests.
* Launch: **Advanced Features → Password Audit**.
* Steps:

  1. Load hash file.
  2. Select cracking method (dictionary/brute-force).
  3. Run audit.
  4. Export cracked vs. uncracked list.

---

### 📂 Directory Bruteforcer

**Location:** `app/advanced_features/directory_bruteforcer_widget.py`

* Purpose: Discover hidden directories/files on a web server.
* Launch: **Advanced Features → Directory Bruteforcer**.
* Input: Base URL + wordlist.
* Output: Endpoints with status codes.

---

### 🛡️ Blue-Team Tools

#### Incident Response

**Location:** `app/advanced_features/incident_response.py`

* Purpose: Automate triage & playbooks.
* Launch: **Blue-Team Panel → Incident Response**.
* Input: system/network logs.
* Output: Findings table + remediation suggestions.

#### Honeypot Manager

**Location:** `app/advanced_features/honeypot_manager.py`

* Purpose: Deploy honeypots (SSH/HTTP/SMB).
* Launch: **Advanced Features → Honeypot Manager**.
* Output: Attacker IPs, session logs, IOCs.

#### NAC (Network Access Control)

**Location:** `app/advanced_features/nac.py`, `known_macs.json`

* Purpose: Detect unauthorized devices.
* Launch: **Advanced Features → NAC**.
* Output: Compare detected MACs/IPs with whitelist.

---

### ☁️ Ops Tools

#### Config Manager

**Location:** `app/advanced_features/config_management.py`

* Purpose: Backup and restore device configs.
* Launch: **Advanced Features → Config Manager**.
* Output: Side-by-side diff of configs.

#### Performance Monitoring

**Location:** `app/advanced_features/performance_monitoring.py`

* Purpose: Track CPU, memory, bandwidth.
* Launch: **Advanced Features → Performance Monitor**.
* Output: Real-time graphs.

#### Cloud Dashboard

**Location:** `app/advanced_features/cloud_dashboard.py`

* Purpose: Enumerate AWS, Azure, GCP resources.
* Launch: **Advanced Features → Cloud Dashboard**.
* Output: IAM roles, services, security groups.

---

### 🤖 AI Copilot

**Location:** `app/advanced_features/ai_assistant_widget.py`

* Purpose: Natural-language log analysis & recommendations.
* Launch: **AI Assistant Widget**.
* Usage:

  ```
  Show failed SSH logins from last 24h
  Suggest mitigations for weak TLS finding
  ```
* Output: Highlighted anomalies + suggested fixes.

---

### 🧩 Advanced Red-Team Features

**Location:** `app/core/redteam/*`

* **Nmap Wrapper**: run network scans from GUI.
* **Crypto Tools**: hashing, encoding helpers.
* **Automation Hooks**: for chaining tasks.

---

### 📏 Compliance Checker (Planned)

* Purpose: Validate configs against CIS/NIST benchmarks.
* Launch: (future) **Advanced Features → Compliance Checker**.
* Input: device config backups.
* Output: Pass/Fail report with remediation.

---

## 📷 Snapshots

Add GIFs/screenshots to `docs/screenshots/` and link here:

* Recon: `docs/screenshots/recon.gif`
* Phishing: `docs/screenshots/phishing.gif`
* Password Audit: `docs/screenshots/password_audit.gif`
* IR: `docs/screenshots/ir.gif`
* Honeypot: `docs/screenshots/honeypot.gif`
* Copilot: `docs/screenshots/copilot.gif`

---

## 🛡️ Disclaimer

This toolkit is for **authorized use only**: internal ops, training, controlled labs.
Unauthorized phishing, brute force, or recon against systems you don’t own is illegal.

---

## ⭐ Roadmap

* [ ] Playbook automation (mini-SOAR).
* [ ] Threat intel enrichment.
* [ ] Interactive topology mapper.
* [ ] Containerized tool launcher (Burp, Wireshark, Zeek).
* [ ] Compliance checker.
* [ ] Collaboration workspace.

---

## 📚 Project Info

* **Repository:** [Blindsinner/NetOpsToolkitPro](https://github.com/Blindsinner/NetOpsToolkitPro)
* **License:** MIT

```
