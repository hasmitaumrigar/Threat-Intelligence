***Cyber Threat Intelligence Dashboard***

## Objective ##
A SOC-style dashboard for cybersecurity threat intelligence investigations. Analysts can investigate IP addresses using **multiple intelligence sources**, visualize threat patterns, track historical investigations, and generate SOC-style reports. This project demonstrates real-world SOC analyst skills.

## Features
- **IP Threat Lookup** – Investigate any IP address.
- **Multi-Source Threat Intelligence** – Queries AbuseIPDB, VirusTotal, and AlienVault OTX.
- **Unified Threat Score & Risk Classification** – Assigns Low, Medium, or High risk based on combined intelligence.
- **High-Risk Alert Panel** – Immediately highlights critical threats in red at the top of the dashboard.
- **Investigation History & Statistics** – Tracks all IPs investigated and displays visual summaries.
- **Global Attacker Heatmap** – Visualizes attacker locations worldwide.
- **Downloadable PDF Reports** – Export investigation results in SOC-style reports.
- **Dark Theme UI** – Professional SOC-style look.


## Installation

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

***Live Demo***

Try the dashboard live on Streamlit Community Cloud:
https://share.streamlit.io/

***How It Works***

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

**Learning Outcomes**

Built a multi-source threat intelligence investigation tool.
Learned SOC-style risk scoring and alerting.
Developed interactive dashboards with Streamlit and pydeck.
Practiced API integration and secure key management.
Gained experience in data visualization and reporting for security operations.

***Tools & Technologies***

Python – Core language

Streamlit – Interactive dashboard

Pandas – Data processing

Requests – API queries

Matplotlib / pydeck – Visualization & maps

fpdf – PDF report generation

APIs: AbuseIPDB, VirusTotal, AlienVault OTX
