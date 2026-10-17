Markdown
# AI-Powered Hybrid Cloud SOC: AWS Infrastructure & On-Premise MikroTik Security Operations via Wazuh SIEM

An autonomous hybrid security operations monitoring infrastructure integrating Amazon Web Services (AWS) cloud telemetry and an on-premise MikroTik edge router into a centralized Wazuh SIEM deployed on AWS. The platform provides unified visibility across cloud control planes and local perimeter defenses, backed by a bounded AI SOC Agent. Local Ollama is the default model runtime, with optional Google Gemini support. The agent can adaptively call read-only tools against ChromaDB incident memory, Wazuh Indexer telemetry, and configured threat-intelligence providers. Tool calls are validated and audited locally. TheHive case creation is an optional post-investigation operation and is reported as created only after a real API response confirms it.

---

## Incident Verification and Safe-Operation Notes

### LLM Provider Configuration

Ollama is the default backend. Ensure the model exists in your Ollama installation and set these variables in the SOC agent process environment when needed:

```bash
export SOC_LLM_PROVIDER=ollama
export SOC_OLLAMA_URL=http://127.0.0.1:11434/api/chat
export SOC_OLLAMA_MODEL=qwen2.5:7b
export SOC_OLLAMA_TIMEOUT_SECONDS=180
export SOC_AGENT_MAX_TOOL_STEPS=6
export SOC_AUDIT_LOG_PATH=logs/agent_audit.jsonl
export SOC_THEHIVE_AUTO_CREATE=false
```

Use `SOC_OLLAMA_URL` to point at a protected local endpoint or an explicitly configured SSH tunnel. Do not expose Ollama's API directly to the public internet. Choose a model that supports tool calling. To use the optional Gemini path, set `SOC_LLM_PROVIDER=gemini`, `GEMINI_API_KEY`, and optionally `GEMINI_MODEL`.

The investigation loop defaults to six tool calls per alert and clamps the configured budget to twelve. The JSONL audit log is written to the configured path, which defaults to logs/agent_audit.jsonl. To create real TheHive cases, set THEHIVE_URL and THEHIVE_API_KEY, then explicitly enable SOC_THEHIVE_AUTO_CREATE=true. TLS verification is enabled by default; install a trusted certificate or set THEHIVE_VERIFY_TLS=false only in an isolated test lab.


### Verification, Containment, and Transport

- **Classification is evidence-based triage:** a Wazuh rule level determines prioritization, not proof of compromise. Reports without enough evidence default to `suspicious` / human review rather than an automatically confirmed true positive.
- **Containment is not currently automated:** `trigger_containment_action` returns `NOT_CONFIGURED` and `not_executed`. It deliberately does not claim to isolate a host or block an address. A real Wazuh Active Response adapter must be configured, tested, and audited before automated containment is enabled.
- **Dashboard status reflects recorded evidence:** new records default to `Not executed`. An event is only shown as `Executed & Verified` when its stored status explicitly says `EXECUTED_AND_VERIFIED`.
- **Threat-intelligence status is explicit:** missing keys, API errors, and rate limits are recorded as unavailable or partial results, not as a clean reputation result.
- **Adaptive investigation:** the model selects read-only tools based on the incoming alert, receives results, and reassesses before choosing the next step. Agent-scoped Indexer searches are restricted to the alert's agent ID; IP/hash lookups must reference observed indicators.
- **Tool audit trail:** each tool attempt records the incident ID, tool name, bounded arguments, result status, duration, and a short result excerpt in a local JSONL file. The audit log is excluded from Git.
- **TheHive is opt-in:** the model cannot create cases directly. A separate orchestration step can create one only after the report, when SOC_THEHIVE_AUTO_CREATE=true and THEHIVE_API_KEY are configured. No credentials means no case creation.
- **TLS verification:** Wazuh API and Indexer verify TLS by default through `WAZUH_API_VERIFY_TLS=true` and `WAZUH_INDEXER_VERIFY_TLS=true`. TheHive also verifies TLS by default through `THEHIVE_VERIFY_TLS=true`. In an isolated lab using self-signed certificates, each setting can be explicitly set to `false`; prefer installing and trusting the correct CA certificate.
- **Existing vector-store records:** metadata created before these changes may not contain rule-level or containment-status fields. The dashboard treats absent containment status as `Not executed`, but historical classifications may still reflect the older classifier and should be reviewed before using them as ground truth.

## Architecture Overview

+-------------------------------------------------------------------------------------------------------------+
|                                                  AWS CLOUD                                                  |
|                                                                                                             |
|   +-----------------------+     Wazuh AWS Module / API     +--------------------------------------------+   |
|   | AWS Services          | =============================> | AWS EC2 Instance                           |   |
|   | - CloudTrail (Audit)  |       (S3 Bucket Logs)         | - Wazuh Manager, Indexer & Dashboard       |   |
|   | - IAM / Security Grps |                                | - OpenVPN Server + rsyslog                 |   |
|   +-----------------------+                                +--------------------------------------------+   |
|                                                                    |                 ^                      |
|                                                     High-Severity  |                 |                      |
|                                                     Alerts (JSON)  v                 |                      |
|                                                        +----------------------------------------+           |
|                                                        | Autonomous AI SOC Agent (Python)       |           |
|                                                        | - Ollama (default) / Gemini (optional) |           |
|                                                        | - ChromaDB Vector Retrieval (RAG)      |           |
|                                                        | - Automated Triage & Incident Reports  |           |
|                                                        +----------------------------------------+           |
+--------------------------------------------------------------------------------------|----------------------+
|
Encrypted OpenVPN Tunnel (UDP 1194)      |
Syslog Telemetry Forwarding (UDP 514)    |
v
+----------------------------------+
|   On-Premise Network             |
|   - MikroTik RouterOS (Client)   |
|   - Firewall & Auth Event Logs   |
+----------------------------------+


---

## Tech Stack & Core Components

| Layer / Domain | Technology | Implementation Role |
| :--- | :--- | :--- |
| **SIEM Platform** | Wazuh v4.x (Manager, Indexer, Dashboard) | Central log collection, correlation engine, and visualizations |
| **Cloud Provider** | Amazon Web Services (AWS) | Cloud host (VPC, EC2, IAM Policies, S3 Buckets, Security Groups) |
| **Cloud Auditing** | AWS CloudTrail & S3 Ingestion | Ingesting control plane API calls, IAM modifications, and login events |
| **Edge Router** | MikroTik RouterOS | Telemetry source for network perimeter, dropped traffic, and admin auth |
| **Secure Transit** | OpenVPN | Site-to-Cloud encrypted tunnel preventing public exposure of Syslog data |
| **Log Routing** | Remote Syslog (`rsyslog`) | Ingesting MikroTik UDP log stream on the private VPN interface |
| **AI Investigation** | Python, Ollama (local default), optional Gemini, ChromaDB | Alert contextualization, local historical retrieval, and triage reporting |

---

## Detection Capabilities & Use Cases

### 1. AWS Cloud Security Monitoring
* **IAM & Privilege Abuse:** Detection of root account logins, unauthorized policy attachments, and MFA-disabled sessions.
* **Infrastructure Changes:** Alerts on modifications to VPC Security Groups, Route Tables, and Internet Gateways.
* **Storage & Resource Access:** Auditing unauthorized S3 bucket access and sensitive API termination requests.

### 2. MikroTik Perimeter Defense
* **Brute-Force Detection:** Tracking repeated authentication failures across Winbox, WebFig, and SSH.
* **Reconnaissance & Scans:** Identifying TCP/UDP port scans and dropped packet spikes on the WAN interface.
* **Administrative Auditing:** Logging RouterOS configuration changes, script executions, and user additions.

### 3. Autonomous AI Incident Triage
* **Automated Alert Contextualization:** Correlates high-severity Wazuh alerts against historical incidents stored in ChromaDB.
* **Threat Scoring & Summarization:** Evaluates true-positive probability and produces plain-language executive summaries.
* **Prescriptive Remediation:** Outlines immediate mitigation steps (e.g., firewall block rules, IAM credential revocation).

---

## Repository Structure

```text
├── configs/
│   ├── aws/
│   │   ├── wazuh-aws-module.xml.template   # Wazuh ossec.conf S3/CloudTrail bucket configuration
│   │   └── iam-least-privilege-policy.json # Read-only IAM policy for Wazuh log ingestion
│   ├── mikrotik/
│   │   └── logging-setup.rsc               # RouterOS syslog forwarding and firewall logging rules
│   ├── wazuh/
│   │   ├── custom_decoders.xml             # Decoders tailored for MikroTik and custom event structures
│   │   └── custom_rules.xml                # Detection rules for RouterOS attack vectors
│   └── openvpn/
│       └── server.conf.template            # Sanitized OpenVPN server configuration
├── diagrams/
│   └── architecture-topology.png           # Network and data flow architecture diagram
├── docs/
│   ├── aws-wazuh-dashboard.png             # Visualizations of AWS CloudTrail events
│   ├── mikrotik-alerts.png                 # Snapshots of detected RouterOS network alerts
│   ├── ai-triage-report.png                # Sample automated AI investigation output
│   └── openvpn-status.png                  # Active Site-to-Cloud tunnel verification
└── scripts/
    ├── soc_agent.py                        # Alert intake, report generation, memory persistence, optional TheHive case
    ├── investigation_agent.py              # Bounded adaptive tool loop, policy checks, and JSONL audit trail
    ├── agent_tools.py                      # Read-only evidence tools and controlled tool dispatch
    ├── indexer_tool.py                     # Wazuh Indexer process, network, and related-alert queries
    ├── threat_intel.py                     # Reputation checks with explicit provider status
    ├── thehive_tool.py                     # Optional TheHive case/observable/task adapter
    └── requirements.txt                    # Python runtime dependencies
Implementation & Integration Steps
1. AWS Cloud Integration with Wazuh
Created a dedicated AWS S3 bucket and CloudTrail trail capturing multi-region management events.

Provisioned an IAM Role with least-privilege s3:GetObject and s3:ListBucket permissions for the Wazuh manager.

Configured <wodle name="aws-s3"> in ossec.conf to poll CloudTrail logs via the AWS SDK.

2. OpenVPN Site-to-Cloud Tunnel
Deployed OpenVPN server on the AWS EC2 instance hosting Wazuh.

Configured MikroTik RouterOS as an OpenVPN client using dedicated client certificates.

Established a private subnet bridge allowing the router to route syslog traffic without exposing ports to the public internet.

3. MikroTik Log Parsing & Correlation
Configured /system logging action in RouterOS targeting the Wazuh private OpenVPN interface (10.8.0.1:514).

Implemented regex decoders and custom rules (Rule IDs 100100+) to parse RouterOS log formats and flag anomalous activity.

4. Autonomous AI SOC Agent Integration
Developed an AI triage pipeline in Python (soc_agent.py) triggered by high-severity Wazuh alerts.

Configured the SOC agent to use the local Ollama HTTP API by default (model: `qwen2.5:7b`), with Google Gemini available when `SOC_LLM_PROVIDER=gemini`. Both provider paths can adaptively call the bounded read-only tool set, including ChromaDB history retrieval, Wazuh Indexer searches, and configured threat-intelligence checks.

Integrated ChromaDB vector store for similarity search across historical incidents to enrich investigation reports.

Security Best Practices Applied
No Plaintext Ingestion: Edge logs are transported over an encrypted VPN tunnel; cloud logs are pulled via encrypted HTTPS endpoints using IAM authentication.

Credential Sanitation: All production AWS Account IDs, Access Keys, Public IPs, and Private Certificates have been removed or replaced with placeholder templates.

API Key Isolation: Gemini API credentials and cloud secrets are ingested strictly through environment variables.

Granular Access Control: EC2 security groups restrict administrative access exclusively through trusted management endpoints.

Project Roadmap
[x] AWS Infrastructure & CloudTrail Log Ingestion

[x] On-Premise MikroTik Integration via OpenVPN

[x] Custom Log Decoders and Detection Rule Engineering

[x] AI-Driven Threat Triage: Ollama/Gemini adaptive tool calling with ChromaDB memory, Wazuh Indexer enrichment, provider-status validation, and tool audit logging.

[ ] Automated Active Response: Real endpoint isolation or MikroTik/Wazuh response adapters are not implemented. The current agent records recommendations and does not execute containment.