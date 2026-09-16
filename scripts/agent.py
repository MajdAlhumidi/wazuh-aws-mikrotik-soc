import json
from wazuh_parser import parse_wazuh_alert, format_alert_for_llm
from tools import investigate_historical_incidents

# يمكن استبدال هذه الدالة باستدعاء مباشر لـ OpenAI / Ollama / Anthropic
def run_soc_agent(raw_wazuh_alert: dict):
    print("=" * 60)
    print("[*] 1. New Wazuh Alert Received. Parsing...")
    alert_info = parse_wazuh_alert(raw_wazuh_alert)
    alert_text = format_alert_for_llm(alert_info)
    print(f"[+] Rule Triggered: {alert_info['rule_description']}")

    print("\n[*] 2. Querying Vector Database for historical patterns...")
    # استدعاء أداة البحث الدلالي
    historical_matches = investigate_historical_incidents(alert_text)
    print(historical_matches)

    print("[*] 3. Synthesizing Decision (AI Agent Evaluation)...")
    
    # بناء Prompt التقييم
    agent_prompt = f"""
    You are an automated L1 SOC Analyst.
    Evaluate the following incoming Wazuh alert against historical incidents.
    
    === INCOMING WAZUH ALERT ===
    {alert_text}
    
    === HISTORICAL INCIDENTS CONTEXT ===
    {historical_matches}
    
    Task:
    1. Determine if this alert is a TRUE POSITIVE or FALSE POSITIVE.
    2. Provide confidence score (0-100%).
    3. State the operational reasoning based on the similarity with past incidents.
    """
    
    # محاكاة منطق تقرير الـ Agent (أو تمرير agent_prompt لنموذجك الذكي)
    print("\n--- [AGENT TRIAGE REPORT] ---")
    print(f"Target Alert ID: {alert_info['alert_id']}")
    print("Verdict Suggestion: Analysis completed based on similarity distance.")
    print("Agent Investigation Context Ready for LLM Pipeline.")
    print("=" * 60)

if __name__ == "__main__":
    # تنبيه تجريبي مشابه لما ينتجه Wazuh عند تشغيل PowerShell
    sample_wazuh_alert = {
        "timestamp": "2026-09-05T14:30:00.000+0000",
        "rule": {
            "level": 8,
            "description": "Suspicious PowerShell Encoded Command",
            "id": "100201"
        },
        "agent": {
            "id": "001",
            "name": "win-server-prod",
            "ip": "10.10.4.15"
        },
        "data": {
            "srcip": "10.10.1.20",
            "dstip": "10.10.4.15",
            "srcuser": "SYSTEM"
        },
        "full_log": "PowerShell execution detected running encoded script block from SCCM maintenance job."
    }

    run_soc_agent(sample_wazuh_alert)
