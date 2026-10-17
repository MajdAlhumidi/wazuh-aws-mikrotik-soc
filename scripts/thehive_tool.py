import os
import json
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# إعدادات الاتصال بـ TheHive (يمكن تمريرها عبر متغيرات البيئة)
THEHIVE_URL = os.getenv("THEHIVE_URL", "http://localhost:9000")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "")
THEHIVE_VERIFY_TLS = os.getenv("THEHIVE_VERIFY_TLS", "true").strip().lower() in {"1", "true", "yes", "on"}

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
        endpoint = f"{THEHIVE_URL}/api/v1/case" if "/v1" in THEHIVE_URL else f"{THEHIVE_URL}/api/case"
        res = requests.post(endpoint, headers=headers, json=case_payload, verify=THEHIVE_VERIFY_TLS, timeout=10)
        
        if res.status_code not in [200, 201]:
            return json.dumps({"status": "error", "message": f"Failed to create case: {res.text}"})

        case_data = res.json()
        case_id = case_data.get("_id") or case_data.get("id")

        # 2. إضافة الـ Observables إن وجدت
        if observables and case_id:
            obs_url = f"{THEHIVE_URL}/api/case/{case_id}/observable"
            for obs in observables:
                obs_payload = {
                    "dataType": obs.get("type", "other"),
                    "data": obs.get("value"),
                    "message": obs.get("description", "Extracted by SOC Agent"),
                    "tlp": 2
                }
                requests.post(obs_url, headers=headers, json=obs_payload, verify=THEHIVE_VERIFY_TLS, timeout=10)

        # 3. إنشاء مهام المتابعة (Tasks)
        if tasks and case_id:
            task_url = f"{THEHIVE_URL}/api/case/{case_id}/task"
            for task_title in tasks:
                requests.post(task_url, headers=headers, json={"title": task_title}, verify=THEHIVE_VERIFY_TLS, timeout=10)

        return json.dumps({
            "status": "success",
            "case_id": case_id,
            "title": title,
            "message": f"TheHive Case {case_id} generated with {len(observables or [])} observables and {len(tasks or [])} tasks."
        })

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
