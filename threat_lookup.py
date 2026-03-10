import requests

API_KEY = "703b04879eb5a80a1b3d32d410773297af6648ef677434d073bf4bab7d1a335c121003804d0a58eb"

def lookup_ip(ip):
    """Query AbuseIPDB and return IP threat information."""
    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    response = requests.get(url, headers=headers, params=params)
    data = response.json().get("data", {})

    # Handle cases where AbuseIPDB returns incomplete data
    result = {
        "IP": data.get("ipAddress", "N/A"),
        "Country": data.get("countryCode", "N/A"),
        "ISP": data.get("isp", "N/A"),
        "Abuse Score": data.get("abuseConfidenceScore", 0),
        "Reports": data.get("totalReports", 0)
    }

    return result