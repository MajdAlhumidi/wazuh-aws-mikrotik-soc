from pydantic import BaseModel, Field
from typing import Literal, List, Optional
from datetime import datetime


class IncidentRecord(BaseModel):
    incident_id: str
    rule_name: str
    classification: Literal["true_positive", "false_positive"]
    analyst_notes: str
    diagnostic_and_audit_notes: str = Field(
        default="",
        description="Technical and API diagnostic notes (e.g., resolved ImportErrors, API live query status, telemetry health)."
    )
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

    alert_summary: str
    source_ip: str
    destination_ip: str
    user_account: str
    raw_logs: str

    def to_document_text(self) -> str:
        text = (
            f"Alert Rule: {self.rule_name}\n"
            f"Summary: {self.alert_summary}\n"
            f"Target User: {self.user_account}\n"
            f"Network: {self.source_ip} -> {self.destination_ip}\n"
            f"Evidence Logs: {self.raw_logs}\n"
            f"Analyst Conclusion: {self.analyst_notes}"
        )
        if self.diagnostic_and_audit_notes:
            text += f"\nDiagnostic & Audit Notes: {self.diagnostic_and_audit_notes}"
        return text

    def to_metadata(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "rule_name": self.rule_name,
            "classification": self.classification,
            "analyst_notes": self.analyst_notes,
            "diagnostic_notes": self.diagnostic_and_audit_notes,
            "timestamp": self.timestamp,
            "user_account": self.user_account
        }


class IncidentReport(BaseModel):
    """مخطط التقرير النهائي المُنتج بواسطة وكيل الذكاء الاصطناعي (AI Agent Output Schema)"""
    incident_id: str
    verdict: Literal["True Positive", "False Positive", "Suspicious", "Benign"]
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    summary: str
    mitre_techniques: List[str] = Field(default_factory=list)
    recommended_containment: List[str] = Field(default_factory=list)
    diagnostic_and_audit_notes: str = Field(
        default="",
        description="Technical diagnostic notes, API reliability status, and root cause for previous query delays or ImportErrors."
    )
