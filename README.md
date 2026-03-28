## ***Cyber Threat Intelligence Dashboard*** ##

## Objective ##
A SOC-style dashboard for cybersecurity threat intelligence investigations. Analysts can investigate IP addresses using **multiple intelligence sources**, visualize threat patterns, track historical investigations, and generate SOC-style reports. This project demonstrates real-world SOC analyst skills.

## Features
- **IP Threat Lookup** – Investigate any IP address.# Cyber Threat Intelligence Dashboard

A SOC-style threat intelligence dashboard for investigating **IP addresses, domains, and file hashes** using multiple real-time intelligence sources. Built to demonstrate real-world SOC analyst workflows.


## Objective

Analysts can investigate any IOC (Indicator of Compromise), visualize threat patterns, track historical investigations, and generate SOC-style PDF reports — all from a single dashboard.

## Features

- **Multi-IOC Support** — Investigate IP addresses, domains, and file hashes (MD5, SHA1, SHA256)
- **Auto IOC Detection** — Automatically detects and corrects the IOC type from its format
- **Multi-Source Threat Intelligence** — Queries AbuseIPDB, VirusTotal, and AlienVault OTX simultaneously
- **Unified Threat Score** — Calculates a combined risk score across all sources
- **Category-Aware Scoring** — Boosts scores based on VirusTotal threat categories (phishing, malware, botnet, etc.)
- **Risk Classification** — Classifies threats as Low 🟢, Medium 🟠, or High 🔴
- **Unanalyzed Domain Detection** — Warns analysts when a domain has never been scanned by any engine
- **Investigation History** — Tracks all IOCs investigated with visual statistics
- **Risk Distribution Charts** — Bar charts for abuse scores, risk levels, and top attacking countries
- **Live Threat Feed** — Shows the 5 most recent investigations in real time
- **Auto PDF Reports** — Automatically saves SOC-style PDF reports to a local `reports/` folder
- **Downloadable PDF Reports** — Export any investigation result as a PDF with one click
- **Secure Key Management** — API keys stored in Streamlit secrets manager (never hardcoded)

---

## Installation

### 1. Clone the repository
git clone https://github.com/hasmitaumrigar/Threat-Intelligence.git
cd Threat-Intelligence

### 2. Create and activate a virtual environment

python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac/Linux

### 3. Install dependencies

pip install -r requirements.txt

### 4. Add your API keys

Create a `secrets.env` file in the project root:

ABUSEIPDB_KEY=your_real_abuseipdb_key
VT_KEY=your_real_virustotal_key
OTX_KEY=your_real_otx_key

| API | Free Tier | Sign Up |
|-----|-----------|---------|
| AbuseIPDB | 1,000 req/day | abuseipdb.com/register |
| VirusTotal | 4 req/min | virustotal.com |
| AlienVault OTX | Unlimited | otx.alienvault.com |

### 5. Run the dashboard

streamlit run app.py

## Live Demo

Try the dashboard live on Streamlit Community Cloud:

🔗 **[Launch Dashboard](https://threat-intelligence-mhk9z3vwdsx5xmijsqifzd.streamlit.app/)**

## How It Works

1. Select an IOC type — **IP Address**, **Domain**, or **File Hash**
2. Enter any IOC value — the dashboard auto-detects and corrects the type if mismatched
3. Click **Check Threat** — the system queries all three intelligence sources simultaneously
4. Results are displayed **side by side** per source with full metadata
5. A **Unified Risk Score** is calculated using the highest score across all sources
6. **Category intelligence** from VirusTotal boosts scores for phishing, malware, botnet domains
7. Investigation is saved to history and a **PDF report is auto-generated**
8. Charts update automatically — risk distribution, abuse scores, top attacking countries

---

## Test IOCs

| IOC | Type | Expected Result |
|-----|------|----------------|
| `185.220.101.5` | IP | High Risk 🔴 (Tor exit node) |
| `8.8.8.8` | IP | Low Risk 🟢 (Google DNS) |
| `ngrok.io` | Domain | Medium Risk 🟠 (anonymizer) |
| `google.com` | Domain | Low Risk 🟢 |
| `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` | SHA256 | High Risk 🔴 (EICAR test) |

---

## Learning Outcomes

- Built a multi-source threat intelligence investigation tool from scratch
- Implemented SOC-style risk scoring with weighted engine results and category intelligence
- Developed interactive dashboards with Streamlit
- Practiced secure API key management using environment variables and Streamlit secrets
- Gained experience in data visualization and automated PDF reporting for security operations
- Learned real-world IOC investigation workflows used by SOC analysts

---

## Tools & Technologies

| Tool | Purpose |
|------|---------|
| Python | Core language |
| Streamlit | Interactive dashboard |
| Pandas | Data processing & history tracking |
| Requests | API queries |
| fpdf | PDF report generation |
| python-dotenv | Local secrets management |
| AbuseIPDB API | IP reputation & abuse reports |
| VirusTotal API | Multi-engine malware & domain scanning |
| AlienVault OTX API | Threat pulse & geolocation intelligence |

---

## Project Structure

```
Threat-Intelligence/
├── app.py                    # Main Streamlit dashboard
├── multi_threat_lookup.py    # AbuseIPDB, VirusTotal, OTX lookups + IOC detection
├── threat_lookup.py          # IP lookup helper
├── report_generator.py       # PDF report generation
├── requirements.txt          # Python dependencies
├── reports/                  # Auto-saved PDF reports (local only)
├── investigation_history.csv # Investigation log (local only)
└── secrets.env               # API keys (never pushed to GitHub)

- **Multi-Source Threat Intelligence** – Queries AbuseIPDB, VirusTotal, and AlienVault OTX.
- **Unified Threat Score & Risk Classification** – Assigns Low, Medium, or High risk based on combined intelligence.
- **High-Risk Alert Panel** – Immediately highlights critical threats in red at the top of the dashboard.
- **Investigation History & Statistics** – Tracks all IPs investigated and displays visual summaries.
- **Global Attacker Heatmap** – Visualizes attacker locations worldwide.
- **Downloadable PDF Reports** – Export investigation results in SOC-style reports.
- **Dark Theme UI** – Professional SOC-style look.

**## Installation**

1. Clone the repository:
   
git clone https://github.com/hasmitaumrigar/Cyber-Threat-Intelligence.git

cd Cyber-Threat-Intelligence

2. Create and activate a virtual environment:

python -m venv venv

venv\Scripts\activate

3. Install dependencies:

pip install -r requirements.txt

4. Run the dashboard:

streamlit run app.py

*****Live Demo*****

Try the dashboard live on Streamlit Community Cloud:
https://share.streamlit.io/

*****How It Works*****

Enter an IP address to investigate.

**The system queries multiple threat intelligence sources:**
AbuseIPDB
VirusTotal
AlienVault OTX

Displays each source’s results and calculates a Unified Threat Score.
Classifies risk into Low / Medium / High.
Updates investigation history and charts automatically.
Highlights high-risk IPs in a red alert panel at the top.
Optionally export investigation results to a PDF SOC report.

****Learning Outcomes****

Built a multi-source threat intelligence investigation tool.
Learned SOC-style risk scoring and alerting.
Developed interactive dashboards with Streamlit and pydeck.
Practiced API integration and secure key management.
Gained experience in data visualization and reporting for security operations.

*****Tools & Technologies***
**
Python – Core language

Streamlit – Interactive dashboard

Pandas – Data processing

Requests – API queries

Matplotlib / pydeck – Visualization & maps

fpdf – PDF report generation

APIs: AbuseIPDB, VirusTotal, AlienVault OTX
