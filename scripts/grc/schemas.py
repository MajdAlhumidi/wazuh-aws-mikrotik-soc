"""Pydantic request models for the GRC API."""

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


RiskStatus = Literal["open", "mitigating", "accepted", "closed"]
ControlStatus = Literal[
    "not_assessed", "implemented", "partially_implemented",
    "not_implemented", "not_applicable", "needs_review"
]
ApprovalStatus = Literal["approved", "rejected", "changes_requested"]


class RiskCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=200)
    description: str = Field("", max_length=5000)
    category: str = Field("Cybersecurity", max_length=100)
    asset: str = Field("", max_length=200)
    owner: str = Field("", max_length=120)
    likelihood: int = Field(..., ge=1, le=5)
    impact: int = Field(..., ge=1, le=5)
    residual_likelihood: Optional[int] = Field(None, ge=1, le=5)
    residual_impact: Optional[int] = Field(None, ge=1, le=5)
    treatment: str = Field("", max_length=3000)
    status: RiskStatus = "open"


class RiskUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=3, max_length=200)
    description: Optional[str] = Field(None, max_length=5000)
    category: Optional[str] = Field(None, max_length=100)
    asset: Optional[str] = Field(None, max_length=200)
    owner: Optional[str] = Field(None, max_length=120)
    likelihood: Optional[int] = Field(None, ge=1, le=5)
    impact: Optional[int] = Field(None, ge=1, le=5)
    residual_likelihood: Optional[int] = Field(None, ge=1, le=5)
    residual_impact: Optional[int] = Field(None, ge=1, le=5)
    treatment: Optional[str] = Field(None, max_length=3000)
    status: Optional[RiskStatus] = None


class ControlCreate(BaseModel):
    id: str = Field(..., min_length=3, max_length=40)
    title: str = Field(..., min_length=3, max_length=200)
    description: str = Field("", max_length=5000)
    domain: str = Field("Protect", max_length=80)
    framework: str = Field("SHAM Internal Baseline", max_length=100)
    framework_ref: Optional[str] = Field(None, max_length=100)
    implementation_status: ControlStatus = "not_assessed"
    owner: str = Field("", max_length=120)
    review_frequency: str = Field("quarterly", max_length=40)


class ControlUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=3, max_length=200)
    description: Optional[str] = Field(None, max_length=5000)
    domain: Optional[str] = Field(None, max_length=80)
    framework: Optional[str] = Field(None, max_length=100)
    framework_ref: Optional[str] = Field(None, max_length=100)
    implementation_status: Optional[ControlStatus] = None
    owner: Optional[str] = Field(None, max_length=120)
    review_frequency: Optional[str] = Field(None, max_length=40)


class EvidenceCreate(BaseModel):
    risk_id: Optional[str] = None
    control_id: Optional[str] = None
    source: str = Field(..., min_length=2, max_length=80)
    reference_id: str = Field("", max_length=300)
    description: str = Field(..., min_length=3, max_length=2000)
    sha256: Optional[str] = Field(None, min_length=64, max_length=64)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    collected_by: str = Field("unspecified", max_length=120)


class WazuhEvidenceInput(BaseModel):
    alert_id: str = Field(..., min_length=1, max_length=200)
    rule_id: str = Field("", max_length=40)
    rule_level: Optional[int] = Field(None, ge=0, le=20)
    rule_description: str = Field("", max_length=500)
    agent_id: str = Field("", max_length=40)
    agent_name: str = Field("", max_length=120)
    timestamp: str = Field("", max_length=80)
    source_ip: str = Field("", max_length=64)
    summary: str = Field(..., min_length=3, max_length=2000)
    risk_id: Optional[str] = None
    control_ids: List[str] = Field(default_factory=list)


class AgentAssessmentInput(BaseModel):
    incident_id: str = Field(..., min_length=1, max_length=200)
    classification: str = Field(..., min_length=2, max_length=80)
    severity: str = Field(..., min_length=2, max_length=40)
    summary: str = Field(..., min_length=3, max_length=2000)
    confidence: Optional[float] = Field(None, ge=0, le=1)
    model_name: str = Field("", max_length=120)
    model_version: str = Field("", max_length=120)
    recommendations: List[str] = Field(default_factory=list)
    risk_id: Optional[str] = None
    control_ids: List[str] = Field(default_factory=list)


class ApprovalCreate(BaseModel):
    reference_type: Literal["incident", "risk", "control_change", "response_action"]
    reference_id: str = Field(..., min_length=1, max_length=200)
    requested_action: str = Field(..., min_length=3, max_length=1000)
    requested_by: str = Field("unspecified", max_length=120)


class ApprovalDecision(BaseModel):
    status: ApprovalStatus
    decided_by: str = Field(..., min_length=2, max_length=120)
    decision_note: str = Field("", max_length=2000)
