# multi_threat_lookup.py — All lookup functions + IOC detection
 
import re
import requests
from dotenv import load_dotenv
load_dotenv()
# -------------------------------
# API Keys
# -------------------------------
ABUSEIPDB_KEY = "9b98bed5be88352dee8f15b6aa4da50da57e0e9781b440b88b8f5c6fb434bc99ec15fefc2b52b9a0"
VT_KEY = "8396bc735ce56ccd679a2690f76dbaccfc99d959311abc4d118287971c5be39e"
OTX_KEY = "8cefcbea66bfced732d9ce10f8c5bdc84db9afbef8efca1a24a9d1c4e32e703e"
# -------------------------------
# IOC Type Auto-Detection
# -------------------------------
IOC_PATTERNS = {
    "MD5":        re.compile(r"^[a-fA-F0-9]{32}$"),
    "SHA1":       re.compile(r"^[a-fA-F0-9]{40}$"),
    "SHA256":     re.compile(r"^[a-fA-F0-9]{64}$"),
    "Domain":     re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    ),
    "IP Address": re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$"),
}
 
def detect_ioc_type(value: str) -> str:
    value = value.strip()
    for ioc_type, pattern in IOC_PATTERNS.items():
        if pattern.match(value):
            if ioc_type in ("MD5", "SHA1", "SHA256"):
                return "File Hash"
            return ioc_type
    return "Unknown"
 
 
# -------------------------------
# High-risk category keywords that boost the score
# -------------------------------
HIGH_RISK_CATEGORIES = {
    "phishing", "malware", "malicious", "ransomware", "botnet",
    "exploit", "trojan", "spyware", "adware", "spam", "anonymizer",
    "tor", "proxy", "vpn", "cryptomining", "c2", "command and control",
    "booter", "ddos", "brute force", "credential stuffing", "dark web",}
 
MEDIUM_RISK_CATEGORIES = {
    "suspicious", "fraud", "scam", "hacking", "parked",
    "dynamic dns", "url shortener", "tracking", "information technology",
}
 
def category_score_boost(categories: dict) -> int:
    """
    Returns a score boost (0-50) based on VT category labels.
    High-risk keywords add up to 50 points.
    Medium-risk keywords add up to 20 points.
    """
    if not categories:
        return 0
    
    all_labels = " ".join(str(v) for v in categories.values()).lower()
    for keyword in HIGH_RISK_CATEGORIES:
        if keyword in all_labels:
            return 50   
    for keyword in MEDIUM_RISK_CATEGORIES:
        if keyword in all_labels:
            return 20
    return 0
 
 
# -------------------------------
# malicious=full, suspicious=half, categories add boost
# -------------------------------
def calculate_vt_score(stats: dict, categories: dict = None) -> int:
    malicious  = stats.get("malicious",  0)
    suspicious = stats.get("suspicious", 0)
    harmless   = stats.get("harmless",   0)
    undetected = stats.get("undetected", 0)
    total      = sum(stats.values()) if stats else 0

    engine_score = 0
    if total > 0:
        weighted     = malicious + (suspicious * 0.5)
        engine_score = int((weighted / total) * 100)

    if total > 0 and harmless == 0 and malicious == 0 and undetected == total:
        engine_score = 30 

    boost = category_score_boost(categories or {})
    return min(engine_score + boost, 100)
# -------------------------------
# AbuseIPDB — IP lookup
# -------------------------------
def check_abuseipdb(ip: str) -> dict:
    url     = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params  = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        r.raise_for_status()
        data = r.json().get("data", {})
        return {
            "source":      "AbuseIPDB",
            "IP":          data.get("ipAddress", ip),
            "Country":     data.get("countryCode", "N/A"),
            "ISP":         data.get("isp", "N/A"),
            "Abuse Score": data.get("abuseConfidenceScore", 0),
            "Reports":     data.get("totalReports", 0),
            "Domain":      data.get("domain", "N/A"),
            "Usage Type":  data.get("usageType", "N/A"),
        }
    except requests.exceptions.RequestException as e:
        return {
            "source": "AbuseIPDB", "Error": str(e),
            "Abuse Score": 0, "Country": "N/A",
        }
 
 
# -------------------------------
# VirusTotal — domain + file hash + IP
# -------------------------------
def check_virustotal(ioc: str, ioc_type: str = "domain") -> dict:
    if ioc_type == "file":
        length = len(ioc.strip())
        if length not in (32, 40, 64):
            return {
                "source":          "VirusTotal",
                "IOC":             ioc,
                "Status":          f"⚠️ Invalid hash length ({length} chars). Must be MD5=32, SHA1=40, SHA256=64.",
                "Malicious Count": 0,
                "Total Engines":   0,
                "Abuse Score":     0,
                "Country":         "N/A",
            }
    endpoint_map = {
        "domain": f"https://www.virustotal.com/api/v3/domains/{ioc}",
        "file":   f"https://www.virustotal.com/api/v3/files/{ioc}",
        "ip":     f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
    }
    url     = endpoint_map.get(ioc_type, endpoint_map["domain"])
    headers = {"x-apikey": VT_KEY}
 
    try:
        r = requests.get(url, headers=headers, timeout=10)
 
        if r.status_code == 404:
            return {
                "source":          "VirusTotal",
                "IOC":             ioc,
                "Status":          "⚠️ Not found in VirusTotal database",
                "Malicious Count": 0,
                "Suspicious":      0,
                "Harmless":        0,
                "Undetected":      0,
                "Total Engines":   0,
                "Abuse Score":     0,
                "Country":         "N/A",
            }
 
        r.raise_for_status()
        attributes  = r.json().get("data", {}).get("attributes", {})
        stats       = attributes.get("last_analysis_stats", {})
        categories  = attributes.get("categories", {})
 
        abuse_score = calculate_vt_score(stats, categories)
 
        result = {
            "source":          "VirusTotal",
            "IOC":             ioc,
            "Malicious Count": stats.get("malicious",  0),
            "Suspicious":      stats.get("suspicious", 0),
            "Harmless":        stats.get("harmless",   0),
            "Undetected":      stats.get("undetected", 0),
            "Total Engines":   sum(stats.values()) if stats else 0,
            "Abuse Score":     abuse_score,
            "Country":         "N/A",
        }
 
        if ioc_type == "domain":
            result["Registrar"]     = attributes.get("registrar", "N/A")
            result["Creation Date"] = attributes.get("creation_date", "N/A")
            result["Categories"]    = categories  # return as dict, not string
 
        if ioc_type == "file":
            result["File Type"] = attributes.get("type_description", "N/A")
            result["File Name"] = str(attributes.get("names", ["N/A"])[:3])
            result["File Size"] = attributes.get("size", "N/A")
 
        if ioc_type == "ip":
            result["AS Owner"] = attributes.get("as_owner", "N/A")
            result["Country"]  = attributes.get("country", "N/A")
 
        return result
 
    except requests.exceptions.RequestException as e:
        return {
            "source": "VirusTotal", "IOC": ioc,
            "Malicious Count": 0, "Total Engines": 0,
            "Abuse Score": 0, "Country": "N/A",
            "Error": str(e),
        }
 
 
# -------------------------------
# OTX AlienVault
# -------------------------------
def validate_otx_key() -> bool:
    """Quick check that the OTX key is valid before making lookups."""
    if not OTX_KEY or OTX_KEY == "YOUR_OTX_KEY":
        return False
    try:
        r = requests.get(
            "https://otx.alienvault.com/api/v1/user/me",
            headers={"X-OTX-API-KEY": OTX_KEY},
            timeout=5,
        )
        return r.status_code == 200
    except Exception:
        return False
 
def check_otx(ioc: str, ioc_type: str = "IPv4") -> dict:
    otx_type_map = {
        "domain":   "hostname",  
        "hostname": "hostname",
        "IPv4":     "IPv4",
        "ip":       "IPv4",
        "file":     "file",
    }
    otx_type = otx_type_map.get(ioc_type, ioc_type)
    url      = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{ioc}/general"
    headers  = {"X-OTX-API-KEY": OTX_KEY}
 
    if not OTX_KEY or OTX_KEY == "YOUR_OTX_KEY":
        return {
            "source":      "OTX AlienVault",
            "IOC":         ioc,
            "Pulse Count": 0,
            "Country":     "N/A",
            "Abuse Score": 0,
            "Error":       "OTX API key not configured",
        }
 
    try:
        r = requests.get(url, headers=headers, timeout=20)
        r.raise_for_status()
        data        = r.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        abuse_score = min(pulse_count * 5, 100)
        return {
            "source":      "OTX AlienVault",
            "IOC":         ioc,
            "Pulse Count": pulse_count,
            "Country":     data.get("country_name", "N/A"),
            "Abuse Score": abuse_score,
            "Tags":        data.get("pulse_info", {}).get("tags", []),
        }
    except requests.exceptions.RequestException as e:
        return {
            "source":      "OTX AlienVault",
            "IOC":         ioc,
            "Pulse Count": 0,
            "Country":     "N/A",
            "Abuse Score": 0,
            "Error":       str(e),
        }
 
def check_domain(domain: str) -> dict:
    result = check_virustotal(domain, ioc_type="domain")
    result["Domain"] = result.pop("IOC", domain)
    return result
 
def check_file_hash(file_hash: str) -> dict:
    result = check_virustotal(file_hash, ioc_type="file")
    result["File Hash"] = result.pop("IOC", file_hash)
    return result
 