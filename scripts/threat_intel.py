import os
import re
import ipaddress
import requests
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")
VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GREYNOISE_KEY = os.getenv("GREYNOISE_API_KEY")


def is_valid_public_ip(ip: str) -> bool:
    """التحقق من صحة الـ IP وتجاهل الشبكات الداخلية والـ Loopback."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved)
    except ValueError:
        return False


def is_valid_hash(file_hash: str) -> bool:
    """التحقق من طول وصيغة الهاش (MD5, SHA1, SHA256)."""
    clean = file_hash.strip().lower()
    return bool(re.fullmatch(r"([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})", clean))


def check_abuseipdb(ip: str) -> dict:
    if not ABUSEIPDB_KEY:
        return {"abuse_score": 0, "total_reports": 0, "country": "N/A", "isp": "N/A"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}

    try:
        res = requests.get(url, headers=headers, params=params, timeout=5)
        if res.status_code == 200:
            data = res.json().get("data", {})
            return {
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country": data.get("countryCode", "N/A"),
                "isp": data.get("isp", "Unknown")
            }
        elif res.status_code == 429:
            print("[!] AbuseIPDB: Daily Rate Limit reached.")
    except Exception as e:
        print(f"[!] AbuseIPDB Error: {e}")

    return {"abuse_score": 0, "total_reports": 0, "country": "N/A", "isp": "Unknown"}


def check_virustotal(ip: str) -> dict:
    if not VT_KEY:
        return {"malicious": 0, "suspicious": 0}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_KEY}

    try:
        res = requests.get(url, headers=headers, timeout=5)
        if res.status_code == 200:
            stats = res.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0)
            }
        elif res.status_code == 429:
            print("[!] VirusTotal: Rate limit reached (4 req/min).")
    except Exception as e:
        print(f"[!] VirusTotal Error: {e}")

    return {"malicious": 0, "suspicious": 0}


def check_greynoise(ip: str) -> dict:
    if not GREYNOISE_KEY:
        return {"noise": False, "riot": False, "classification": "unknown"}

    url = f"https://api.greynoise.io/v3/community/{ip}"
    headers = {"key": GREYNOISE_KEY, "Accept": "application/json"}

    try:
        res = requests.get(url, headers=headers, timeout=5)
        if res.status_code == 200:
            data = res.json()
            return {
                "noise": data.get("noise", False),
                "riot": data.get("riot", False),
                "classification": data.get("classification", "unknown")
            }
    except Exception as e:
        print(f"[!] GreyNoise Error: {e}")

    return {"noise": False, "riot": False, "classification": "unknown"}


def check_ip_reputation(ip: str) -> dict:
    """تقييم سمعة عنوان IP."""
    if not is_valid_public_ip(ip):
        return {
            "ip": ip,
            "classification": "INTERNAL_OR_PRIVATE",
            "severity": "LOW",
            "recommended_action": "IGNORE",
            "details": "Private or loopback IP."
        }

    abuse = check_abuseipdb(ip)
    vt = check_virustotal(ip)
    gn = check_greynoise(ip)

    score = abuse["abuse_score"]
    vt_malicious = vt["malicious"]
    is_noise = gn["noise"]
    is_riot = gn["riot"]

    if is_riot:
        classification = "BENIGN_SERVICE"
        action = "ALLOW"
        severity = "LOW"
    elif score >= 50 or vt_malicious >= 3:
        classification = "MALICIOUS_HOST"
        action = "BLOCK"
        severity = "CRITICAL"
    elif is_noise or score >= 20 or vt_malicious >= 1:
        classification = "SUSPICIOUS_SCANNER"
        action = "RATE_LIMIT"
        severity = "MEDIUM"
    else:
        classification = "CLEAN_OR_UNKNOWN"
        action = "MONITOR"
        severity = "LOW"

    return {
        "ip": ip,
        "classification": classification,
        "severity": severity,
        "recommended_action": action,
        "details": {
            "abuse_score": score,
            "abuse_reports": abuse["total_reports"],
            "vt_malicious_engines": vt_malicious,
            "isp": abuse.get("isp"),
            "country": abuse.get("country")
        }
    }


def check_file_hash(file_hash: str) -> dict:
    """تقييم سمعة تجزئة الملف (MD5, SHA1, SHA256) عبر VirusTotal."""
    clean_hash = file_hash.strip().lower()

    if not is_valid_hash(clean_hash):
        return {
            "hash": clean_hash,
            "status": "INVALID_HASH_FORMAT",
            "severity": "INFORMATIONAL",
            "recommended_action": "IGNORE"
        }

    if not VT_KEY:
        return {
            "hash": clean_hash,
            "status": "VT_API_KEY_MISSING",
            "severity": "UNKNOWN",
            "recommended_action": "MANUAL_REVIEW"
        }

    url = f"https://www.virustotal.com/api/v3/files/{clean_hash}"
    headers = {"x-apikey": VT_KEY}

    try:
        res = requests.get(url, headers=headers, timeout=6)
        if res.status_code == 200:
            data = res.json().get("data", {})
            attr = data.get("attributes", {})
            stats = attr.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            threat_label = attr.get("popular_threat_classification", {}).get("suggested_threat_label", "N/A")
            meaningful_name = attr.get("meaningful_name", "Unknown")
            file_type = attr.get("type_description", "Unknown")

            if malicious >= 3:
                classification = "MALICIOUS_BINARY"
                severity = "CRITICAL"
                action = "KILL_PROCESS_AND_QUARANTINE"
            elif malicious in (1, 2) or suspicious > 0:
                classification = "SUSPICIOUS_BINARY"
                severity = "HIGH"
                action = "ISOLATE_HOST_AND_INSPECT"
            else:
                classification = "BENIGN_FILE"
                severity = "LOW"
                action = "ALLOW"

            return {
                "hash": clean_hash,
                "classification": classification,
                "severity": severity,
                "recommended_action": action,
                "file_info": {
                    "suggested_name": meaningful_name,
                    "file_type": file_type,
                    "threat_family": threat_label,
                    "malicious_engines": malicious,
                    "suspicious_engines": suspicious,
                    "total_engines": sum(stats.values())
                }
            }
        elif res.status_code == 404:
            return {
                "hash": clean_hash,
                "classification": "UNKNOWN_OR_NEW_HASH",
                "severity": "MEDIUM",
                "recommended_action": "SUBMIT_TO_SANDBOX",
                "details": "Hash not found in VirusTotal database."
            }
        elif res.status_code == 429:
            print("[!] VirusTotal: Rate limit reached (4 req/min).")
    except Exception as e:
        print(f"[!] VirusTotal Hash Error: {e}")

    return {
        "hash": clean_hash,
        "classification": "ERROR_QUERYING_VT",
        "severity": "UNKNOWN",
        "recommended_action": "MANUAL_REVIEW"
    }
