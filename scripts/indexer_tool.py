import os
import json
import urllib3
from opensearchpy import OpenSearch

# إعدادات الاتصال بـ Wazuh Indexer
INDEXER_HOST = os.getenv("WAZUH_INDEXER_HOST", "https://localhost:9200")
INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "")
INDEXER_PASS = os.getenv("WAZUH_INDEXER_PASS", "")
INDEXER_VERIFY_TLS = os.getenv("WAZUH_INDEXER_VERIFY_TLS", "true").strip().lower() in {"1", "true", "yes", "on"}

if not INDEXER_VERIFY_TLS:
    # Only suppress warnings when an isolated lab explicitly disables verification.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_opensearch_client() -> OpenSearch:
    return OpenSearch(
        hosts=[INDEXER_HOST],
        http_auth=(INDEXER_USER, INDEXER_PASS),
        verify_certs=INDEXER_VERIFY_TLS,
        ssl_show_warn=INDEXER_VERIFY_TLS,
        timeout=10,
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

def query_related_alerts(agent_id: str, query_text: str = "", time_range_minutes: int = 60, size: int = 10) -> str:
    """Search recent Wazuh alerts for one agent, optionally ranked by investigative context."""
    try:
        minutes = max(1, min(int(time_range_minutes), 240))
    except (TypeError, ValueError):
        minutes = 60
    try:
        limit = max(1, min(int(size), 25))
    except (TypeError, ValueError):
        limit = 10

    query_text = str(query_text or "").strip()[:500]
    bool_query = {
        "must": [{"match": {"agent.id": str(agent_id)}}],
        "filter": [{"range": {"timestamp": {"gte": "now-{}m".format(minutes)}}}],
    }
    if query_text:
        bool_query["should"] = [{
            "multi_match": {
                "query": query_text,
                "fields": [
                    "rule.description^3", "rule.id^2", "full_log",
                    "data.srcip", "data.dstip", "agent.name",
                ],
                "type": "best_fields",
                "operator": "or",
            }
        }]
        bool_query["minimum_should_match"] = 0

    query = {
        "query": {"bool": bool_query},
        "size": limit,
        "sort": [{"_score": {"order": "desc"}}, {"timestamp": {"order": "desc"}}],
    }
    try:
        response = get_opensearch_client().search(body=query, index="wazuh-alerts-4.x-*")
        hits = response.get("hits", {}).get("hits", [])
        alerts = []
        for hit in hits:
            src = hit.get("_source", {})
            data = src.get("data") or {}
            rule = src.get("rule") or {}
            agent = src.get("agent") or {}
            alerts.append({
                "timestamp": src.get("timestamp"),
                "agent_id": agent.get("id"),
                "agent_name": agent.get("name"),
                "rule_id": rule.get("id"),
                "rule_level": rule.get("level"),
                "rule_description": rule.get("description"),
                "source_ip": data.get("srcip") or data.get("src_ip"),
                "destination_ip": data.get("dstip") or data.get("dst_ip"),
                "user": data.get("dstuser") or data.get("srcuser") or data.get("user"),
                "full_log": str(src.get("full_log") or "")[:1200],
            })
        return json.dumps({
            "status": "success" if alerts else "empty",
            "agent_id": str(agent_id),
            "time_range_minutes": minutes,
            "count": len(alerts),
            "alerts": alerts,
        }, ensure_ascii=False, default=str)
    except Exception as exc:
        return json.dumps({
            "status": "error",
            "agent_id": str(agent_id),
            "message": "Wazuh Indexer related-alert query failed: {}".format(exc),
        }, ensure_ascii=False)


if __name__ == "__main__":
    print("[*] Testing Wazuh Indexer connectivity...")
    test_agent_id = "001"
    print(f"[*] Querying recent process executions on Agent {test_agent_id}:")
    print(query_process_tree(agent_id=test_agent_id, time_range_minutes=60))
