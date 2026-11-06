# SHAM AI GRC Foundation

This package adds a focused Governance, Risk and Compliance layer to the existing
Wazuh / MikroTik Hybrid SOC repository. It is intentionally separate from the
incident-analysis logic.

## Scope

- Risk register with a transparent 5x5 likelihood-impact score.
- Internal control catalogue, seeded once into SQLite.
- Risk-to-control mappings.
- Evidence references from Wazuh and SHAM AI assessments.
- Human approval records for consequential actions.
- Append-only audit events at the application/database-trigger level.
- A compliance implementation indicator that is explicitly not a certification.

The initial control catalogue is an internal starting baseline. It is not a
validated NIST, ISO 27001, or regulatory control mapping. A responsible
security/GRC owner must review and map controls to the selected framework
before using the dashboard for formal compliance reporting.

## Storage

SQLite is used to avoid adding a new runtime dependency. The default database
path is data/grc.sqlite3 relative to the repository root.

Set GRC_DB_PATH to move the database, for example:

    export GRC_DB_PATH=/var/lib/sham-ai/grc.sqlite3

The data directory and SQLite files must be backed up and excluded from Git.

## API integration

The router is mounted by scripts/api_server.py under /api/grc.

Useful endpoints:

- GET /api/grc/health
- GET, POST /api/grc/risks
- GET, PATCH /api/grc/risks/{risk_id}
- GET, POST, PATCH /api/grc/controls
- POST /api/grc/risks/{risk_id}/controls/{control_id}
- GET /api/grc/risks/{risk_id}/controls
- GET, POST /api/grc/evidence
- GET /api/grc/compliance/summary
- GET, POST /api/grc/approvals
- PATCH /api/grc/approvals/{approval_id}/decision
- GET /api/grc/audit-logs
- POST /api/grc/integrations/wazuh/evidence
- POST /api/grc/integrations/sham-ai/assessment

Write endpoints accept an optional X-Actor header for audit attribution. This
header is an attribution field, not authentication or identity verification.

## Wazuh evidence example

    {
      "alert_id": "1234567890",
      "rule_id": "100100",
      "rule_level": 10,
      "rule_description": "Repeated failed Winbox logins",
      "agent_id": "001",
      "agent_name": "edge-router",
      "timestamp": "2026-11-06T16:00:00Z",
      "source_ip": "192.0.2.10",
      "summary": "Repeated authentication failures were observed.",
      "control_ids": ["SHAM-LOG-001", "SHAM-IR-001"]
    }

The endpoint stores a concise evidence reference and a SHA-256 fingerprint;
it does not store the complete raw Wazuh event.

## SHAM AI assessment example

    {
      "incident_id": "INC-TEST-001",
      "classification": "SUSPICIOUS",
      "severity": "HIGH",
      "summary": "The agent identified repeated authentication failures.",
      "confidence": 0.82,
      "model_name": "local-model",
      "model_version": "configured-version",
      "recommendations": ["Review source address", "Verify account activity"],
      "control_ids": ["SHAM-AI-001", "SHAM-IR-001"]
    }

This endpoint records an AI-generated assessment as evidence only. It does not
approve, execute, or represent containment. The analyst's final decision must
be recorded separately.

## Risk scoring

Score = likelihood (1-5) x impact (1-5):

- 1-4: Low
- 5-9: Medium
- 10-16: High
- 17-25: Critical

Residual risk is calculated only when both residual likelihood and residual
impact are supplied.

## Security deployment notes

The existing FastAPI application does not show an authentication layer in its
current API routes. The GRC router follows that existing pattern and therefore
must not be exposed directly to an untrusted network. Put it behind the
project's authenticated access layer or a trusted reverse proxy before
production use. Restrict access to write endpoints, protect the SQLite file,
define evidence retention, and back up the database.

The GRC module does not perform automated response or containment.
