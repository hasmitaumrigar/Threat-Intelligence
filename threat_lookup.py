# threat_lookup.py
import requests

ABUSEIPDB_KEY = "9b98bed5be88352dee8f15b6aa4da50da57e0e9781b440b88b8f5c6fb434bc99ec15fefc2b52b9a0"

RESERVED_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "::1"}

def is_valid_ip(ip: str) -> bool:
    """Reject reserved/unroutable IPs before lookup."""
    if ip in RESERVED_IPS:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False

def lookup_ip(ip: str) -> dict:
    if not is_valid_ip(ip):
        return {
            "IP": ip,
            "Country": "N/A",
            "ISP": "N/A",
            "Abuse Score": 0,
            "Reports": 0,
            "Error": f"Invalid or reserved IP address: {ip}"
        }

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json().get("data", {})
        return {
            "IP": data.get("ipAddress", ip),
            "Country": data.get("countryCode", "N/A"),
            "ISP": data.get("isp", "N/A"),
            "Abuse Score": data.get("abuseConfidenceScore", 0),
            "Reports": data.get("totalReports", 0),
        }
    except requests.exceptions.RequestException as e:
        return {
            "IP": ip,
            "Country": "N/A",
            "ISP": "N/A",
            "Abuse Score": 0,
            "Reports": 0,
            "Error": str(e)
        }