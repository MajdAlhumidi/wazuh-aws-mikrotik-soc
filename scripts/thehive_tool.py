import os
import json
import requests
import urllib3

# إعدادات الاتصال بـ TheHive (يمكن تمريرها عبر متغيرات البيئة)
THEHIVE_URL = os.getenv("THEHIVE_URL", "http://localhost:9000").rstrip("/")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "")
THEHIVE_VERIFY_TLS = os.getenv("THEHIVE_VERIFY_TLS", "true").strip().lower() in {"1", "true", "yes", "on"}
THEHIVE_API_VERSION = os.getenv("THEHIVE_API_VERSION", "v4").strip().lower()

if not THEHIVE_VERIFY_TLS:
    # Only silence certificate warnings when a lab explicitly disables verification.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _thehive_api_url(resource: str) -> str:
    """Build a version-correct TheHive API URL from a base host URL."""
    api_prefix = "/api/v1" if THEHIVE_API_VERSION in {"v5", "5", "5.x"} else "/api"
    return "{}/{}".format(THEHIVE_URL + api_prefix, str(resource).lstrip("/"))

# خريطة تحويل مستويات الخطورة إلى أرقام TheHive (1: Low, 2: Medium, 3: High, 4: Critical)
SEVERITY_MAP = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4
}

def create_thehive_incident_case(
    title: str,
    severity: str,
    description: str,
    mitre_tags: list = None,
    observables: list = None,
    tasks: list = None
) -> str:
    """
    إنشاء Case متكاملة على منصة TheHive مع الأدلة والمهام للمحللين.
    """
    severity_level = SEVERITY_MAP.get(severity.lower(), 2)
    tags = ["AI-SOC-Agent", "Wazuh-RAMv2"]
    if mitre_tags:
        tags.extend(mitre_tags)

    case_payload = {
        "title": title,
        "description": description,
        "severity": severity_level,
        "tags": tags,
        "flag": severity.lower() in ["high", "critical"],
        "tlp": 2, # TLP:AMBER
        "pap": 2
    }

    # إذا لم يكن هناك API Key حقيقي، تعمل الأداة بوضع المحاكاة الميدانية
    if not THEHIVE_API_KEY:
        not_created = {
            "status": "not_configured",
            "mode": "NO LIVE CASE CREATED (Set THEHIVE_API_KEY and SOC_THEHIVE_AUTO_CREATE=true)",
            "title": title,
            "severity": severity.upper(),
            "tags": tags,
            "observables_count": len(observables) if observables else 0,
            "tasks_assigned": tasks if tasks else [],
            "message": "TheHive API key is missing; no live case was created."
        }
        print(f"\n[!] [TheHive] Case NOT created: {title}. Configure THEHIVE_API_KEY and explicitly enable SOC_THEHIVE_AUTO_CREATE.")
        return json.dumps(not_created)

    # الاتصال الفعلي بـ TheHive API (v4 / v5)
    headers = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Content-Type": "application/json"
    }

    try:
        # 1. إنشاء الـ Case
        endpoint = _thehive_api_url("case")
        res = requests.post(endpoint, headers=headers, json=case_payload, verify=THEHIVE_VERIFY_TLS, timeout=10)

        if res.status_code not in [200, 201]:
            return json.dumps({"status": "error", "message": "Failed to create case: {}".format(res.text)})

        case_data = res.json()
        case_id = case_data.get("_id") or case_data.get("id")
        if not case_id:
            return json.dumps({
                "status": "error",
                "message": "TheHive returned a successful response without a case identifier; creation could not be verified.",
            })

        followup_errors = []
        observables_created = 0
        tasks_created = 0

        # 2. إضافة الـ Observables إن وجدت; capture failures instead of silently claiming success.
        if observables:
            obs_url = _thehive_api_url("case/{}/observable".format(case_id))
            for obs in observables:
                value = obs.get("value")
                obs_payload = {
                    "dataType": obs.get("type", "other"),
                    "data": [value] if THEHIVE_API_VERSION in {"v5", "5", "5.x"} else value,
                    "message": obs.get("description", "Extracted by SOC Agent"),
                    "tlp": 2,
                }
                try:
                    child_res = requests.post(obs_url, headers=headers, json=obs_payload, verify=THEHIVE_VERIFY_TLS, timeout=10)
                    if child_res.status_code in [200, 201, 204]:
                        observables_created += 1
                    else:
                        followup_errors.append({
                            "resource": "observable",
                            "status_code": child_res.status_code,
                            "message": child_res.text[:300],
                        })
                except Exception as child_exc:
                    followup_errors.append({"resource": "observable", "message": str(child_exc)[:300]})

        # 3. إنشاء مهام المتابعة (Tasks)
        if tasks:
            task_url = _thehive_api_url("case/{}/task".format(case_id))
            for task_title in tasks:
                try:
                    child_res = requests.post(task_url, headers=headers, json={"title": task_title}, verify=THEHIVE_VERIFY_TLS, timeout=10)
                    if child_res.status_code in [200, 201, 204]:
                        tasks_created += 1
                    else:
                        followup_errors.append({
                            "resource": "task",
                            "status_code": child_res.status_code,
                            "message": child_res.text[:300],
                        })
                except Exception as child_exc:
                    followup_errors.append({"resource": "task", "message": str(child_exc)[:300]})

        result = {
            "status": "partial" if followup_errors else "success",
            "case_id": case_id,
            "title": title,
            "observables_created": observables_created,
            "tasks_created": tasks_created,
            "message": "TheHive case created; {} observables and {} tasks confirmed.".format(observables_created, tasks_created),
        }
        if followup_errors:
            result["followup_errors"] = followup_errors
        return json.dumps(result)

    except Exception as e:
        return json.dumps({"status": "error", "message": f"TheHive connection error: {str(e)}"})

if __name__ == "__main__":
    # تجربة سريعة للأداة
    test_result = create_thehive_incident_case(
        title="[High] Suspicious PowerShell on finance-srv",
        severity="high",
        description="Execution of Base64 encoded IEX payload detected on finance server.",
        mitre_tags=["T1059.001", "T1027"],
        observables=[
            {"type": "hostname", "value": "finance-srv", "description": "Target server"},
            {"type": "command", "value": "powershell.exe -enc SQBFAFgA...", "description": "Obfuscated payload"}
        ],
        tasks=["Inspect Event ID 4104", "Acquire Memory Dump", "Force Credential Reset"]
    )
    print(test_result)
