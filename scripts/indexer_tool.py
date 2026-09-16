import os
import json
import urllib3
from opensearchpy import OpenSearch

# تعطيل تحذيرات الشهادات غير الموثوقة (Self-signed certificates)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# إعدادات الاتصال بـ Wazuh Indexer
INDEXER_HOST = os.getenv("WAZUH_INDEXER_HOST", "https://localhost:9200")
INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "admin")
INDEXER_PASS = os.getenv("WAZUH_INDEXER_PASS", "admin") # عدّل كلمة المرور إذا كانت مختلفة لديك

def get_opensearch_client() -> OpenSearch:
    return OpenSearch(
        hosts=[INDEXER_HOST],
        http_auth=(INDEXER_USER, INDEXER_PASS),
        verify_certs=False,
        ssl_show_warn=False
    )

def query_process_tree(agent_id: str, time_range_minutes: int = 30) -> str:
    client = get_opensearch_client()
    query = {
        "query": {
            "bool": {
                "must": [
                    {"match": {"agent.id": agent_id}},
                    {"range": {"timestamp": {"gte": f"now-{time_range_minutes}m"}}}
                ],
                "should": [
                    {"term": {"data.win.system.eventID": "1"}},
                    {"match": {"rule.groups": "sysmon_process-creation"}},
                    {"match": {"rule.groups": "auditd"}}
                ],
                "minimum_should_match": 1
            }
        },
        "size": 10,
        "sort": [{"timestamp": {"order": "desc"}}]
    }
    
    try:
        response = client.search(body=query, index="wazuh-alerts-4.x-*")
        hits = response["hits"]["hits"]
        
        if not hits:
            return f"No raw process creation logs found for Agent {agent_id} in the last {time_range_minutes}m."
        
        extracted_events = []
        for hit in hits:
            src = hit["_source"]
            win_data = src.get("data", {}).get("win", {}).get("eventdata", {})
            audit_data = src.get("data", {}).get("audit", {})
            
            event_summary = {
                "timestamp": src.get("timestamp"),
                "process_name": win_data.get("originalFileName") or win_data.get("image") or audit_data.get("command"),
                "command_line": win_data.get("commandLine") or audit_data.get("execve"),
                "parent_process": win_data.get("parentImage") or audit_data.get("parent_command"),
                "parent_command_line": win_data.get("parentCommandLine"),
                "user": win_data.get("user") or src.get("data", {}).get("dstuser")
            }
            extracted_events.append(event_summary)
            
        return json.dumps(extracted_events, indent=2)
    except Exception as e:
        return f"Error querying Indexer for process tree: {str(e)}"

def query_network_activity(agent_id: str, time_range_minutes: int = 30) -> str:
    client = get_opensearch_client()
    query = {
        "query": {
            "bool": {
                "must": [
                    {"match": {"agent.id": agent_id}},
                    {"range": {"timestamp": {"gte": f"now-{time_range_minutes}m"}}}
                ],
                "should": [
                    {"term": {"data.win.system.eventID": "3"}},
                    {"match": {"rule.groups": "firewall"}},
                    {"match": {"rule.groups": "netfilter"}}
                ],
                "minimum_should_match": 1
            }
        },
        "size": 10,
        "sort": [{"timestamp": {"order": "desc"}}]
    }
    
    try:
        response = client.search(body=query, index="wazuh-alerts-4.x-*")
        hits = response["hits"]["hits"]
        
        if not hits:
            return f"No network connection logs found for Agent {agent_id} in the last {time_range_minutes}m."
            
        extracted_conns = []
        for hit in hits:
            src = hit["_source"]
            win_data = src.get("data", {}).get("win", {}).get("eventdata", {})
            
            conn_summary = {
                "timestamp": src.get("timestamp"),
                "image": win_data.get("image"),
                "destination_ip": win_data.get("destinationIp") or src.get("data", {}).get("dstip"),
                "destination_port": win_data.get("destinationPort") or src.get("data", {}).get("dstport"),
                "protocol": win_data.get("protocol") or src.get("data", {}).get("protocol")
            }
            extracted_conns.append(conn_summary)
            
        return json.dumps(extracted_conns, indent=2)
    except Exception as e:
        return f"Error querying Indexer for network activity: {str(e)}"

if __name__ == "__main__":
    print("[*] Testing Wazuh Indexer connectivity...")
    test_agent_id = "001"
    print(f"[*] Querying recent process executions on Agent {test_agent_id}:")
    print(query_process_tree(agent_id=test_agent_id, time_range_minutes=60))
