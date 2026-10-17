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
        return {
            "status": "not_configured",
            "abuse_score": None,
            "total_reports": None,
            "country": "N/A",
            "isp": "N/A",
        }

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    try:
        res = requests.get(url, headers=headers, params=params, timeout=5)
        if res.status_code == 200:
            data = res.json().get("data", {})
            return {
                "status": "ok",
                "abuse_score": data.get("abuseConfidenceScore"),
                "total_reports": data.get("totalReports"),
                "country": data.get("countryCode", "N/A"),
                "isp": data.get("isp", "Unknown"),
            }
        if res.status_code == 429:
            return {"status": "rate_limited", "http_status": 429, "abuse_score": None, "total_reports": None}
        return {
            "status": "http_error",
            "http_status": res.status_code,
            "abuse_score": None,
            "total_reports": None,
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc), "abuse_score": None, "total_reports": None}


def check_virustotal(ip: str) -> dict:
    if not VT_KEY:
        return {"status": "not_configured", "malicious": None, "suspicious": None}

    url = "https://www.virustotal.com/api/v3/ip_addresses/{}".format(ip)
    headers = {"x-apikey": VT_KEY}
    try:
        res = requests.get(url, headers=headers, timeout=5)
        if res.status_code == 200:
            stats = res.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "status": "ok",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
            }
        if res.status_code == 429:
            return {"status": "rate_limited", "http_status": 429, "malicious": None, "suspicious": None}
        return {
            "status": "http_error",
            "http_status": res.status_code,
            "malicious": None,
            "suspicious": None,
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc), "malicious": None, "suspicious": None}


def check_greynoise(ip: str) -> dict:
    if not GREYNOISE_KEY:
        return {
            "status": "not_configured",
            "noise": None,
            "riot": None,
            "classification": "unknown",
        }

    url = "https://api.greynoise.io/v3/community/{}".format(ip)
    headers = {"key": GREYNOISE_KEY, "Accept": "application/json"}
    try:
        res = requests.get(url, headers=headers, timeout=5)
        if res.status_code == 200:
            data = res.json()
            return {
                "status": "ok",
                "noise": data.get("noise", False),
                "riot": data.get("riot", False),
                "classification": data.get("classification", "unknown"),
            }
        if res.status_code == 429:
            return {
                "status": "rate_limited",
                "http_status": 429,
                "noise": None,
                "riot": None,
                "classification": "unknown",
            }
        return {
            "status": "http_error",
            "http_status": res.status_code,
            "noise": None,
            "riot": None,
            "classification": "unknown",
        }
    except Exception as exc:
        return {
            "status": "error",
            "error": str(exc),
            "noise": None,
            "riot": None,
            "classification": "unknown",
        }


def check_ip_reputation(ip: str) -> dict:
    """Do not treat missing credentials or failed provider requests as a clean reputation result."""
    if not is_valid_public_ip(ip):
        try:
            address = ipaddress.ip_address(ip)
            classification = (
                "INTERNAL_OR_PRIVATE"
                if address.is_private or address.is_loopback
                else "NON_PUBLIC_OR_RESERVED"
            )
        except ValueError:
            classification = "INVALID_IP"
        return {
            "status": "not_applicable",
            "ip": ip,
            "classification": classification,
            "severity": "INFORMATIONAL",
            "recommended_action": "MANUAL_REVIEW",
            "details": "External reputation lookup was not performed for an invalid, private, loopback, or reserved address.",
        }

    abuse = check_abuseipdb(ip)
    vt = check_virustotal(ip)
    gn = check_greynoise(ip)
    statuses = {
        "abuseipdb": abuse.get("status", "unknown"),
        "virustotal": vt.get("status", "unknown"),
        "greynoise": gn.get("status", "unknown"),
    }
    successful = [name for name, status in statuses.items() if status == "ok"]
    if not successful:
        all_unconfigured = all(status == "not_configured" for status in statuses.values())
        return {
            "status": "not_configured" if all_unconfigured else "unavailable",
            "ip": ip,
            "classification": "UNKNOWN",
            "severity": "UNKNOWN",
            "recommended_action": "MANUAL_REVIEW",
            "provider_status": statuses,
            "details": "No provider returned usable reputation evidence; this is not a clean verdict.",
        }

    abuse_score = (abuse.get("abuse_score") or 0) if statuses["abuseipdb"] == "ok" else 0
    vt_malicious = (vt.get("malicious") or 0) if statuses["virustotal"] == "ok" else 0
    vt_suspicious = (vt.get("suspicious") or 0) if statuses["virustotal"] == "ok" else 0
    is_noise = bool(gn.get("noise")) if statuses["greynoise"] == "ok" else False
    is_riot = bool(gn.get("riot")) if statuses["greynoise"] == "ok" else False

    if is_riot:
        classification, action, severity = "BENIGN_SERVICE", "MONITOR", "LOW"
    elif abuse_score >= 50 or vt_malicious >= 3:
        classification, action, severity = "MALICIOUS_HOST", "MANUAL_REVIEW", "CRITICAL"
    elif is_noise or abuse_score >= 20 or vt_malicious >= 1 or vt_suspicious > 0:
        classification, action, severity = "SUSPICIOUS_SCANNER", "MANUAL_REVIEW", "MEDIUM"
    else:
        classification, action, severity = "CLEAN_OR_UNKNOWN", "MONITOR", "LOW"

    return {
        "status": "success" if len(successful) == len(statuses) else "partial",
        "ip": ip,
        "classification": classification,
        "severity": severity,
        "recommended_action": action,
        "provider_status": statuses,
        "details": {
            "abuse_score": abuse.get("abuse_score") if statuses["abuseipdb"] == "ok" else None,
            "abuse_reports": abuse.get("total_reports") if statuses["abuseipdb"] == "ok" else None,
            "vt_malicious_engines": vt.get("malicious") if statuses["virustotal"] == "ok" else None,
            "vt_suspicious_engines": vt.get("suspicious") if statuses["virustotal"] == "ok" else None,
            "greynoise_classification": gn.get("classification") if statuses["greynoise"] == "ok" else None,
            "isp": abuse.get("isp") if statuses["abuseipdb"] == "ok" else None,
            "country": abuse.get("country") if statuses["abuseipdb"] == "ok" else None,
        },
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
