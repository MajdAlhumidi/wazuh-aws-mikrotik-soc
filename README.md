Markdown
# Hybrid Cloud SOC: AWS Infrastructure & On-Premise MikroTik Security Monitoring via Wazuh SIEM

A hybrid security operations monitoring infrastructure integrating Amazon Web Services (AWS) cloud telemetry and an on-premise MikroTik edge router into a centralized Wazuh SIEM deployed on AWS. The platform provides unified visibility across cloud control planes and local perimeter defenses, utilizing encrypted OpenVPN tunneling and native AWS API log ingestion.

---

## Architecture Overview

+---------------------------------------------------------------------------------------------------+
|                                            AWS CLOUD                                              |
|                                                                                                   |
|   +-----------------------+     Wazuh AWS Module / API     +----------------------------------+   |
|   | AWS Services          | =============================> | AWS EC2 Instance                 |   |
|   | - CloudTrail (Audit)  |       (S3 Bucket Logs)         | - Wazuh Manager, Indexer & UI    |   |
|   | - IAM / Security Grps |                                | - OpenVPN Server + rsyslog       |   |
|   +-----------------------+                                +----------------------------------+   |
|                                                                             ^                     |
+-----------------------------------------------------------------------------|---------------------+
|
Encrypted OpenVPN Tunnel (UDP 1194)      |
Syslog Telemetry Forwarding (UDP 514)    |
v
+----------------------------------+
|   On-Premise Network             |
|   - MikroTik RouterOS (VPN Client)
|   - Firewall & Auth Event Logs   |
+----------------------------------+


---

## Tech Stack & Core Components

| Layer / Domain | Technology | Implementation Role |
| :--- | :--- | :--- |
| **SIEM Platform** | Wazuh v4.x (Manager, Indexer, Dashboard) | Central log collection, correlation engine, and dashboards |
| **Cloud Provider** | Amazon Web Services (AWS) | Cloud host (VPC, EC2, IAM Policies, S3 Buckets, Security Groups) |
| **Cloud Auditing** | AWS CloudTrail & S3 Ingestion | Ingesting control plane API calls, IAM modifications, and login events |
| **Edge Router** | MikroTik RouterOS | Telemetry source for network perimeter, dropped traffic, and admin auth |
| **Secure Transit** | OpenVPN | Site-to-Cloud encrypted tunnel preventing public exposure of Syslog data |
| **Log Routing** | Remote Syslog (`rsyslog`) | Ingesting MikroTik UDP log stream on the private VPN interface |

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
└── docs/
    ├── aws-wazuh-dashboard.png             # Visualizations of AWS CloudTrail events
    ├── mikrotik-alerts.png                 # Snapshots of detected RouterOS network alerts
    └── openvpn-status.png                  # Active Site-to-Cloud tunnel verification
Implementation & Integration Steps
1. AWS Cloud Integration with Wazuh
Created dedicated AWS S3 bucket and CloudTrail trail capturing multi-region management events.

Provisioned an IAM Role/User with least-privilege s3:GetObject and s3:ListBucket permissions for the Wazuh manager.

Configured <wodle name="aws-s3"> in ossec.conf to poll CloudTrail logs via AWS SDK.

2. OpenVPN Site-to-Cloud Tunnel
Deployed OpenVPN server on the AWS EC2 instance hosting Wazuh.

Configured MikroTik RouterOS as an OpenVPN client using dedicated client certificates.

Established a private subnet bridge allowing the router to route syslog traffic without exposing ports to the public internet.

3. MikroTik Log Parsing & Correlation
Configured /system logging action in RouterOS targeting the Wazuh private OpenVPN interface (10.8.0.1:514).

Implemented regex decoders and custom rules (Rule IDs 100100+) to parse RouterOS log formats and generate high-severity alerts for anomalous activity.

Security Best Practices Applied
No Plaintext Ingestion: Edge logs are transported over an encrypted VPN tunnel; cloud logs are pulled via encrypted HTTPS endpoints using IAM authentication.

Credential Sanitation: All production AWS Account IDs, Access Keys, Public IPs, and Private Certificates have been removed or replaced with placeholder templates.

Granular Access Control: EC2 security groups allow administrative access exclusively through trusted management endpoints.

Project Roadmap
[x] AWS Infrastructure & CloudTrail Log Ingestion

[x] On-Premise MikroTik Integration via OpenVPN

[x] Custom Log Decoders and Detection Rule Engineering

[ ] AI-Driven Threat Triage: Integrate Gemini / OpenAI API to summarize alert contexts and generate remediation playbooks.

[ ] Automated Incident Response (SOAR): Connect Shuffle SOAR to automatically push IP blocklists to the MikroTik firewall upon high-confidence alerts.

License
This project is licensed under the MIT License - see the LICENSE file for details.