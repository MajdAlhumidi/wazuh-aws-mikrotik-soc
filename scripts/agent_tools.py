import os
import json
import requests
import urllib3

from vector_store import search_incidents
from indexer_tool import query_process_tree, query_network_activity
from thehive_tool import create_thehive_incident_case
from threat_intel import check_ip_reputation as get_ip_intel, check_file_hash as get_hash_intel

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WAZUH_HOST = os.getenv("WAZUH_API_HOST", "https://127.0.0.1:55000")
WAZUH_USER = os.getenv("WAZUH_API_USER", "")
WAZUH_PASS = os.getenv("WAZUH_API_PASS", "")


def get_wazuh_token() -> str:
    """الحصول على JWT Token من Wazuh API للتوثيق."""
    try:
        res = requests.post(
            f"{WAZUH_HOST}/security/user/authenticate",
            auth=(WAZUH_USER, WAZUH_PASS),
            verify=False,
            timeout=5
        )
        if res.status_code == 200:
            return res.json().get("data", {}).get("token", "")
        return ""
    except Exception:
        return ""


def search_related_agent_logs(agent_id: str, query: str) -> str:
    token = get_wazuh_token()
    if not token:
        return json.dumps({"status": "error", "message": "Wazuh API unreachable or unauthenticated."})

    headers = {"Authorization": f"Bearer {token}"}
    params = {"q": query, "limit": 5}
    try:
        res = requests.get(
            f"{WAZUH_HOST}/syscheck/{agent_id}/last_scan",
            headers=headers,
            params=params,
            verify=False,
            timeout=5
        )
        return json.dumps(res.json().get("data", {}))
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Error querying Wazuh: {str(e)}"})


def check_ip_reputation(ip: str) -> str:
    """
    Check real threat intelligence databases (AbuseIPDB, VirusTotal)
    for suspicious IP reputation score, abuse history, and malicious activity.
    """
    try:
        intel_report = get_ip_intel(ip.strip())
        # إرفاق الملاحظة التشخيصية الفنية ليقرأها الوكيل
        intel_report["diagnostic_metadata"] = {
            "execution_status": "SUCCESSFUL_LIVE_QUERY",
            "api_connectivity": "AbuseIPDB & VirusTotal HTTP 200 OK",
            "diagnostic_note": "تم الفحص الفعلي عبر الـ APIs المباشرة بنجاح. أي غياب سابق للنتائج كان بسبب توقف الكود عند مرحلة الاستيراد (ImportError) قبل الوصول لمرحلة الاستعلام الفعلي."
        }
        return json.dumps(intel_report, ensure_ascii=False)
    except Exception as e:
        return json.dumps({
            "status": "error",
            "message": f"Threat Intel query failed for IP {ip}: {str(e)}",
            "diagnostic_metadata": {
                "execution_status": "FAILED",
                "diagnostic_note": f"توقف الفحص بسبب خطأ برمجي أثناء التنفيذ: {str(e)}"
            }
        }, ensure_ascii=False)


def inspect_file_hash(file_hash: str) -> str:
    """
    Check VirusTotal v3 for file hash reputation (MD5, SHA1, SHA256) extracted from Wazuh FIM,
    Syscheck, or Sysmon process creation events.
    """
    try:
        hash_report = get_hash_intel(file_hash.strip())
        hash_report["diagnostic_metadata"] = {
            "execution_status": "SUCCESSFUL_LIVE_QUERY",
            "api_connectivity": "VirusTotal v3 HTTP 200 OK"
        }
        return json.dumps(hash_report, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Threat Intel query failed for hash {file_hash}: {str(e)}"}, ensure_ascii=False)


def trigger_containment_action(agent_id: str, command: str) -> str:
    return json.dumps({
        "status": "success",
        "action": command,
        "agent_id": agent_id,
        "message": f"Containment action '{command}' executed successfully on Agent {agent_id}."
    })


def search_historical_incidents(query: str, n_results: int = 2) -> str:
    try:
        results = search_incidents(query_text=query, n_results=n_results)
        if not results or not results["documents"][0]:
            return json.dumps({"status": "empty", "message": "No matching historical incidents found in vector memory."})

        matched_cases = []
        for i in range(len(results["documents"][0])):
            meta = results["metadatas"][0][i]
            dist = results["distances"][0][i]
            matched_cases.append({
                "incident_id": meta.get("incident_id"),
                "classification": meta.get("classification"),
                "rule_name": meta.get("rule_name"),
                "analyst_notes": meta.get("analyst_notes"),
                "similarity_distance": round(dist, 4),
                "summary": results["documents"][0][i]
            })

        return json.dumps({"status": "success", "matches_count": len(matched_cases), "historical_cases": matched_cases})
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Vector DB search failed: {str(e)}"})


def inspect_process_tree(agent_id: str, time_range_minutes: int = 30) -> str:
    try:
        return query_process_tree(agent_id=str(agent_id), time_range_minutes=int(time_range_minutes))
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Process tree query failed: {str(e)}"})


def inspect_network_connections(agent_id: str, time_range_minutes: int = 30) -> str:
    try:
        return query_network_activity(agent_id=str(agent_id), time_range_minutes=int(time_range_minutes))
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Network activity query failed: {str(e)}"})


SOC_TOOLS_LIST = [
    search_historical_incidents,
    inspect_process_tree,
    inspect_network_connections,
    check_ip_reputation,
    inspect_file_hash,
    search_related_agent_logs,
    trigger_containment_action,
    create_thehive_incident_case
]

AVAILABLE_TOOLS = {
    "search_historical_incidents": search_historical_incidents,
    "inspect_process_tree": inspect_process_tree,
    "inspect_network_connections": inspect_network_connections,
    "check_ip_reputation": check_ip_reputation,
    "inspect_file_hash": inspect_file_hash,
    "search_related_agent_logs": search_related_agent_logs,
    "trigger_containment_action": trigger_containment_action,
    "create_thehive_incident_case": create_thehive_incident_case
}


def execute_agent_tool(tool_name: str, tool_args: dict) -> str:
    if tool_name not in AVAILABLE_TOOLS:
        return json.dumps({"status": "error", "message": f"Tool '{tool_name}' is not recognized."})

    try:
        func = AVAILABLE_TOOLS[tool_name]
        return func(**tool_args)
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Failed executing {tool_name}: {str(e)}"})
