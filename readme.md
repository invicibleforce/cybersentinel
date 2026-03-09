<div align="center">

# 🛡️ CyberSentinel

### AI-Powered Network Intrusion Detection System

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-ML-orange?style=for-the-badge&logo=scikit-learn&logoColor=white)
![Dash](https://img.shields.io/badge/Dash-Dashboard-00C8FF?style=for-the-badge&logo=plotly&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-Packet%20Capture-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**A hybrid NIDS combining rule-based threat detection, unsupervised ML anomaly detection, and real-time threat intelligence — built to reinforce SOC analyst training.**

[Features](#-features) • [Architecture](#-architecture) • [Installation](#-installation) • [Usage](#-usage) • [How It Works](#-how-it-works) • [Detection Capabilities](#-detection-capabilities)

---

## 📌 Overview

CyberSentinel is a fully functional **hybrid Network Intrusion Detection System (NIDS)** built entirely in Python. It monitors live network traffic, detects both known and unknown threats, cross-references suspicious IPs against global threat intelligence databases, and presents all findings on a **live web dashboard** that refreshes every 5 seconds.

What makes it a genuine AI project is its core detection engine — an **IsolationForest** unsupervised machine learning model that trains on clean baseline traffic and learns to flag anomalies without being explicitly told what attacks look like. This enables detection of zero-day threats that signature-based tools miss.

> Built as a hands-on learning project during SOC analyst training to understand the detection pipelines used in real security operations centers.

---

## Features

| Feature                     | Description |
|-----------------------------|---|
| **Live Packet Capture**     | Raw socket capture via Scapy off any network interface |
| **Port Scan Detection**     | Flags any source IP probing 10+ unique destination ports |
| **DDoS Detection**          | Detects high-volume floods from multiple sources to one target |
| **Data Exfiltration Detection** | Flags abnormally large outbound data transfers |
| **Suspicious Port Detection** | Monitors Metasploit, Tor, Redis, MongoDB, and other sensitive ports |
| **ML Anomaly Detection**    | IsolationForest trained on baseline traffic — catches zero-days |
| **Threat Intelligence**     | Live AbuseIPDB & VirusTotal lookups for known malicious IPs |
| **Real-Time Dashboard**    | Dash + Plotly web UI, auto-refreshes every 5 seconds |
| **Privilege Guard**       | Clear startup error with exact fix instructions if not running as root |

---

## Architecture

CyberSentinel is built as **five independent modules** that communicate through pandas DataFrames. Each module handles one concern and can be swapped or upgraded independently.

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CYBERSENTINEL PIPELINE                      │
│                                                                     │
│  [Network]──▶[Packet Capture]──▶[Threat Detector]──▶[ML Detector]  │
│                                        │                  │         │
│                              [Threat Intelligence]        │         │
│                                        │                  │         │
│                              └─────────▼──────────────────┘         │
│                                   [Live Dashboard]                  │
│                                  127.0.0.1:8050                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Module Breakdown

```
cybersentinel/
│
├── main.py                    # Entry point — wires all modules, manages threads
├── packet_capture.py          # Scapy raw socket capture + privilege guard
├── threat_detector.py         # Rule-based: port scan, DDoS, exfil, suspicious ports
├── ml_anomaly_detector.py     # IsolationForest training, detection, model persistence
├── threat_intelligence.py     # AbuseIPDB & VirusTotal API integration with caching
├── dashboard.py               # Dash + Plotly live dashboard with callback architecture
│
└── baseline_anomaly_model.pkl # Generated after running --baseline (not in repo)
```

---

## Installation

### Prerequisites

- Linux or macOS (recommended — Windows requires [Npcap](https://npcap.com/))
- Python 3.9+
- Root / Administrator privileges (required for raw packet capture)

### Setup

**1. Clone the repository**
```bash
git clone https://github.com/yourusername/cybersentinel.git
cd cybersentinel
```

**2. Create and activate a virtual environment**
```bash
python3 -m venv venv
source venv/bin/activate        # Linux / macOS
# venv\Scripts\activate         # Windows
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

<details>
<summary>📋 requirements.txt</summary>

```
scapy
pandas
scikit-learn
dash
plotly
requests
numpy
```

</details>

**4. (Optional) Set threat intelligence API keys**
```bash
export ABUSEIPDB_KEY=your_abuseipdb_key_here
export VT_KEY=your_virustotal_key_here
```
> Free API keys available at [abuseipdb.com](https://www.abuseipdb.com) and [virustotal.com](https://www.virustotal.com). The system works without them — threat intel lookups are skipped gracefully.

---

## 🖥️ Usage

### Step 1 — Train the ML baseline model (run once on clean traffic)

```bash
sudo venv/bin/python main.py --baseline
```

This captures 500 packets of normal traffic and saves `baseline_anomaly_model.pkl`. Run this **before any attacks or suspicious activity** so the model learns what normal looks like.

### Step 2 — Start the full system

```bash
sudo venv/bin/python main.py
```

### Step 3 — Open the dashboard

```
http://127.0.0.1:8050
```

The dashboard auto-refreshes every 5 seconds. All charts and alerts update in real time.

---

### CLI Options

```
usage: main.py [-h] [--count N] [--interface NAME] [--baseline]
               [--baseline-count N] [--no-intel] [--port N]

optional arguments:
  --count N             Packets to capture per pipeline cycle (default: 200)
  --interface NAME      Network interface to use (default: auto-detect)
  --baseline            Train ML baseline model and exit
  --baseline-count N    Packets to use for baseline training (default: 500)
  --no-intel            Disable AbuseIPDB / VirusTotal API calls
  --port N              Dashboard web server port (default: 8050)
```

### Examples

```bash
# Capture more packets per cycle for higher accuracy
sudo venv/bin/python main.py --count 500

# Specify network interface manually
sudo venv/bin/python main.py --interface eth0

# Run without threat intel (no API keys needed)
sudo venv/bin/python main.py --no-intel

# Train a larger baseline for better ML accuracy
sudo venv/bin/python main.py --baseline --baseline-count 2000
```

---

## How It Works

### Detection Pipeline

Every pipeline cycle follows this flow:

```
Capture Packets
      │
      ▼
Rule-Based Detection ──────────────────────▶ Alerts[]
(Port Scan / DDoS / Exfil / Suspicious Ports)
      │
      ▼
ML Anomaly Detection ──────────────────────▶ Anomaly Scores
(IsolationForest — score each packet)
      │
      ▼
Threat Intelligence (if HIGH/CRITICAL alerts)
(AbuseIPDB + VirusTotal IP lookup) ────────▶ CRITICAL Alerts
      │
      ▼
Update Dashboard
(shared state → Dash callbacks → browser)
```

### The ML Layer — IsolationForest

The machine learning component is what elevates CyberSentinel beyond a simple rule-based tool.

**How IsolationForest works:**
- Builds random decision trees over the feature space
- Normal traffic points are densely clustered — they require many splits to isolate → score near 0
- Anomalous traffic is sparse/unusual — it gets isolated in very few splits → strongly negative score
- The model only needs **clean training data** — no labelled attack examples required (unsupervised)

**Features used for detection:**

| Feature | Why It Matters |
|---|---|
| `packet_size` | Large packets can indicate data exfiltration |
| `connection_frequency` | High rates from one IP indicate scanning |
| `dest_port` | Connections to unusual ports signal reconnaissance |
| `tcp_flags` | SYN/FIN/RST combinations reveal scan types |
| `unique_destinations` | Many targets from one IP = worm/scanner behavior |
| `ttl` | Unusual TTL values may indicate OS fingerprinting |
| `hour / day_of_week` | Traffic at 3am may be anomalous for a given network |

**Critical design decision — train/detect separation:**

```python
# TRAIN once on clean baseline traffic
detector.train(baseline_df, auto_save=True)   # saves model to disk

# DETECT on every new capture — model is never modified
results = detector.detect(live_df)            # read-only inference
```

Training and detection are strictly separated to prevent the model from being "polluted" by the anomalies it is supposed to catch.

### Real-Time Dashboard

The dashboard uses Dash's `dcc.Interval` component to trigger all chart callbacks every 5 seconds:

- Traffic volume time series
- Protocol distribution (TCP / UDP / ICMP)
- Top 10 most active source IPs
- Top 15 destination ports
- Packet size distribution
- Live alert panel with severity color coding

---

## Detection Capabilities

| Threat Type | Module | Trigger Condition | Severity |
|---|---|---|---|
| Port Scan | `ThreatDetector` | ≥10 unique dest ports from 1 source IP | HIGH |
| DDoS | `ThreatDetector` | >5 sources each sending >10 pkts to same dest | CRITICAL |
| Data Exfiltration | `ThreatDetector` | Source sends >3× average outbound data volume | HIGH |
| Suspicious Ports | `ThreatDetector` | >3 IPs hitting Metasploit/Tor/Redis/MongoDB ports | MEDIUM |
| Zero-Day Anomaly | `MLAnomalyDetector` | IsolationForest score below threshold (-0.3) | VARIABLE |
| Known Malicious IP | `ThreatIntelligence` | AbuseIPDB confidence score >50 | CRITICAL |

---

##  Testing the Detection (Demo)

To trigger a port scan alert during a demo or test:

```bash
# In a second terminal (install nmap first)
sudo apt install nmap          # Debian/Ubuntu/Kali
nmap -sS 127.0.0.1
```

Within one pipeline cycle (~5–10 seconds) a **HIGH severity Port Scan alert** will appear on the dashboard.

---

## 🔧 Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| `PermissionError` on startup | Not running as root | Use `sudo venv/bin/python main.py` |
| `ModuleNotFoundError: sklearn` | Wrong Python / pip | Use `sudo venv/bin/python -m pip install scikit-learn` |
| `app.run_server` error | Dash version ≥ 2.x | Change `run_server` to `run` in `dashboard.py` line 188 |
| Dashboard blank / no data | Capture returning empty DataFrame | Check interface name with `ip link show` |
| No ML detections | Baseline model not trained | Run `sudo venv/bin/python main.py --baseline` first |
| Externally managed environment | Kali / Debian Python restriction | Use a virtual environment (see Installation) |

---

##  Tech Stack

| Technology | Role |
|---|---|
| **Python 3** | Core language |
| **Scapy** | Raw packet capture and parsing |
| **pandas** | Data pipeline (DataFrame between modules) |
| **scikit-learn** | IsolationForest ML model |
| **Dash + Plotly** | Real-time web dashboard |
| **requests** | AbuseIPDB & VirusTotal API calls |
| **threading** | Concurrent capture pipeline + dashboard |

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---



<div align="center">

**Built with purpose during SOC analyst training.**

</div>