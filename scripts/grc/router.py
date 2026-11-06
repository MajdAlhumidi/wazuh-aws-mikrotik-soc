"""FastAPI routes for the SHAM AI GRC foundation.

The module records risks, control status, evidence references, human approvals,
and AI assessment provenance. It does not execute containment actions.
"""

import hashlib
import json
import uuid
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Query

from .audit import record_audit
from .db import db_session, initialize_database, utc_now
from .schemas import (
    AgentAssessmentInput,
    ApprovalCreate,
    ApprovalDecision,
    ControlCreate,
    ControlUpdate,
    EvidenceCreate,
    RiskCreate,
    RiskUpdate,
    WazuhEvidenceInput,
)
from .scoring import calculate_risk_score

router = APIRouter(prefix="/grc", tags=["GRC"])
initialize_database()


def _payload_dict(payload):
    if hasattr(payload, "model_dump"):
        return payload.model_dump()
    return payload.dict()


def _row_dict(row):
    return dict(row) if row is not None else None


def _audit_actor(x_actor: str) -> str:
    return (x_actor or "unspecified").strip()[:120] or "unspecified"


def _get_risk(connection, risk_id: str):
    return connection.execute("SELECT * FROM risks WHERE id = ?", (risk_id,)).fetchone()


def _get_control(connection, control_id: str):
    return connection.execute("SELECT * FROM controls WHERE id = ?", (control_id,)).fetchone()


def _insert_evidence(
    connection,
    *,
    risk_id: Optional[str],
    control_id: Optional[str],
    source: str,
    reference_id: str,
    description: str,
    sha256: Optional[str],
    metadata: dict,
    collected_by: str,
) -> str:
    evidence_id = "EVD-" + uuid.uuid4().hex[:12].upper()
    connection.execute(
        """
        INSERT INTO evidence (
            id, risk_id, control_id, source, reference_id, description,
            sha256, metadata_json, collected_by, collected_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            evidence_id, risk_id, control_id, source, reference_id, description,
            sha256, json.dumps(metadata, ensure_ascii=False, default=str),
            collected_by, utc_now(),
        ),
    )
    record_audit(
        connection, collected_by, "evidence.recorded", "evidence", evidence_id,
        after={"source": source, "reference_id": reference_id, "risk_id": risk_id, "control_id": control_id},
    )
    return evidence_id


@router.get("/health")
def grc_health():
    with db_session() as connection:
        risks = connection.execute("SELECT COUNT(*) AS n FROM risks").fetchone()["n"]
        controls = connection.execute("SELECT COUNT(*) AS n FROM controls").fetchone()["n"]
        evidence = connection.execute("SELECT COUNT(*) AS n FROM evidence").fetchone()["n"]
    return {
        "module": "SHAM AI GRC",
        "status": "available",
        "storage": "SQLite",
        "risks": risks,
        "controls": controls,
        "evidence_records": evidence,
    }


@router.get("/risks")
def list_risks(status: Optional[str] = Query(None), limit: int = Query(100, ge=1, le=500)):
    query = "SELECT * FROM risks"
    params = []
    if status:
        query += " WHERE status = ?"
        params.append(status)
    query += " ORDER BY CASE inherent_level WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END, updated_at DESC LIMIT ?"
    params.append(limit)
    with db_session() as connection:
        rows = connection.execute(query, params).fetchall()
    return {"items": [_row_dict(row) for row in rows], "count": len(rows)}


@router.post("/risks", status_code=201)
def create_risk(payload: RiskCreate, x_actor: str = Header(default="unspecified")):
    data = _payload_dict(payload)
    score, level = calculate_risk_score(data["likelihood"], data["impact"])
    residual_score = residual_level = None
    if data["residual_likelihood"] is not None and data["residual_impact"] is not None:
        residual_score, residual_level = calculate_risk_score(
            data["residual_likelihood"], data["residual_impact"]
        )

    risk_id = "RSK-" + uuid.uuid4().hex[:12].upper()
    now = utc_now()
    with db_session() as connection:
        connection.execute(
            """
            INSERT INTO risks (
                id, title, description, category, asset, owner, likelihood, impact,
                inherent_score, inherent_level, residual_likelihood, residual_impact,
                residual_score, residual_level, treatment, status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                risk_id, data["title"], data["description"], data["category"], data["asset"],
                data["owner"], data["likelihood"], data["impact"], score, level,
                data["residual_likelihood"], data["residual_impact"], residual_score,
                residual_level, data["treatment"], data["status"], now, now,
            ),
        )
        after = _row_dict(_get_risk(connection, risk_id))
        record_audit(connection, _audit_actor(x_actor), "risk.created", "risk", risk_id, after=after)
    return after


@router.get("/risks/{risk_id}")
def get_risk(risk_id: str):
    with db_session() as connection:
        row = _get_risk(connection, risk_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Risk not found")
        return _row_dict(row)


@router.patch("/risks/{risk_id}")
def update_risk(risk_id: str, payload: RiskUpdate, x_actor: str = Header(default="unspecified")):
    changes = payload.model_dump(exclude_unset=True) if hasattr(payload, "model_dump") else payload.dict(exclude_unset=True)
    allowed = {
        "title", "description", "category", "asset", "owner", "likelihood", "impact",
        "residual_likelihood", "residual_impact", "treatment", "status",
    }
    changes = {key: value for key, value in changes.items() if key in allowed}
    invalid_nulls = [key for key, value in changes.items() if value is None and key not in {"residual_likelihood", "residual_impact"}]
    if invalid_nulls:
        raise HTTPException(status_code=422, detail=f"Fields cannot be null: {', '.join(invalid_nulls)}")
    if not changes:
        return get_risk(risk_id)

    with db_session() as connection:
        current_row = _get_risk(connection, risk_id)
        if current_row is None:
            raise HTTPException(status_code=404, detail="Risk not found")
        before = _row_dict(current_row)
        current = dict(current_row)
        merged = {**current, **changes}

        if "likelihood" in changes or "impact" in changes:
            score, level = calculate_risk_score(merged["likelihood"], merged["impact"])
            changes["inherent_score"] = score
            changes["inherent_level"] = level

        if "residual_likelihood" in changes or "residual_impact" in changes:
            if merged["residual_likelihood"] is not None and merged["residual_impact"] is not None:
                residual_score, residual_level = calculate_risk_score(
                    merged["residual_likelihood"], merged["residual_impact"]
                )
            else:
                residual_score = residual_level = None
            changes["residual_score"] = residual_score
            changes["residual_level"] = residual_level

        changes["updated_at"] = utc_now()
        columns = ", ".join(f"{key} = ?" for key in changes)
        connection.execute(
            f"UPDATE risks SET {columns} WHERE id = ?",
            [*changes.values(), risk_id],
        )
        after = _row_dict(_get_risk(connection, risk_id))
        record_audit(connection, _audit_actor(x_actor), "risk.updated", "risk", risk_id, before=before, after=after)
        return after


@router.post("/risks/{risk_id}/controls/{control_id}", status_code=201)
def link_risk_control(risk_id: str, control_id: str, notes: str = "", x_actor: str = Header(default="unspecified")):
    with db_session() as connection:
        if _get_risk(connection, risk_id) is None:
            raise HTTPException(status_code=404, detail="Risk not found")
        if _get_control(connection, control_id) is None:
            raise HTTPException(status_code=404, detail="Control not found")
        connection.execute(
            "INSERT OR IGNORE INTO risk_controls (risk_id, control_id, notes, created_at) VALUES (?, ?, ?, ?)",
            (risk_id, control_id, notes[:1000], utc_now()),
        )
        record_audit(
            connection, _audit_actor(x_actor), "risk_control.linked", "risk", risk_id,
            after={"control_id": control_id, "notes": notes[:1000]},
        )
    return {"risk_id": risk_id, "control_id": control_id, "linked": True}


@router.get("/risks/{risk_id}/controls")
def list_risk_controls(risk_id: str):
    with db_session() as connection:
        if _get_risk(connection, risk_id) is None:
            raise HTTPException(status_code=404, detail="Risk not found")
        rows = connection.execute(
            """
            SELECT c.*, rc.notes AS mapping_notes, rc.created_at AS linked_at
            FROM controls c
            JOIN risk_controls rc ON rc.control_id = c.id
            WHERE rc.risk_id = ?
            ORDER BY c.id
            """,
            (risk_id,),
        ).fetchall()
    return {"items": [_row_dict(row) for row in rows], "count": len(rows)}


@router.get("/controls")
def list_controls(status: Optional[str] = Query(None), domain: Optional[str] = Query(None)):
    query = "SELECT * FROM controls WHERE 1 = 1"
    params = []
    if status:
        query += " AND implementation_status = ?"
        params.append(status)
    if domain:
        query += " AND domain = ?"
        params.append(domain)
    query += " ORDER BY domain, id"
    with db_session() as connection:
        rows = connection.execute(query, params).fetchall()
    return {"items": [_row_dict(row) for row in rows], "count": len(rows)}


@router.post("/controls", status_code=201)
def create_control(payload: ControlCreate, x_actor: str = Header(default="unspecified")):
    data = _payload_dict(payload)
    now = utc_now()
    with db_session() as connection:
        if _get_control(connection, data["id"]) is not None:
            raise HTTPException(status_code=409, detail="Control ID already exists")
        connection.execute(
            """
            INSERT INTO controls (
                id, title, description, domain, framework, framework_ref,
                implementation_status, owner, review_frequency, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data["id"], data["title"], data["description"], data["domain"],
                data["framework"], data["framework_ref"], data["implementation_status"],
                data["owner"], data["review_frequency"], now, now,
            ),
        )
        after = _row_dict(_get_control(connection, data["id"]))
        record_audit(connection, _audit_actor(x_actor), "control.created", "control", data["id"], after=after)
    return after


@router.patch("/controls/{control_id}")
def update_control(control_id: str, payload: ControlUpdate, x_actor: str = Header(default="unspecified")):
    changes = payload.model_dump(exclude_unset=True) if hasattr(payload, "model_dump") else payload.dict(exclude_unset=True)
    allowed = {
        "title", "description", "domain", "framework", "framework_ref",
        "implementation_status", "owner", "review_frequency",
    }
    changes = {key: value for key, value in changes.items() if key in allowed}
    invalid_nulls = [key for key, value in changes.items() if value is None and key != "framework_ref"]
    if invalid_nulls:
        raise HTTPException(status_code=422, detail=f"Fields cannot be null: {', '.join(invalid_nulls)}")
    if not changes:
        with db_session() as connection:
            row = _get_control(connection, control_id)
            if row is None:
                raise HTTPException(status_code=404, detail="Control not found")
            return _row_dict(row)

    with db_session() as connection:
        row = _get_control(connection, control_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Control not found")
        before = _row_dict(row)
        changes["updated_at"] = utc_now()
        columns = ", ".join(f"{key} = ?" for key in changes)
        connection.execute(
            f"UPDATE controls SET {columns} WHERE id = ?",
            [*changes.values(), control_id],
        )
        after = _row_dict(_get_control(connection, control_id))
        record_audit(connection, _audit_actor(x_actor), "control.updated", "control", control_id, before=before, after=after)
    return after


@router.post("/evidence", status_code=201)
def create_evidence(payload: EvidenceCreate):
    data = _payload_dict(payload)
    if not data["risk_id"] and not data["control_id"]:
        raise HTTPException(status_code=422, detail="Evidence must be linked to a risk or a control")
    with db_session() as connection:
        if data["risk_id"] and _get_risk(connection, data["risk_id"]) is None:
            raise HTTPException(status_code=404, detail="Risk not found")
        if data["control_id"] and _get_control(connection, data["control_id"]) is None:
            raise HTTPException(status_code=404, detail="Control not found")
        evidence_id = _insert_evidence(connection, **data)
        row = connection.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
    result = _row_dict(row)
    result["metadata"] = json.loads(result.pop("metadata_json"))
    return result


@router.get("/evidence")
def list_evidence(
    risk_id: Optional[str] = Query(None),
    control_id: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
):
    query = "SELECT * FROM evidence WHERE 1 = 1"
    params = []
    if risk_id:
        query += " AND risk_id = ?"
        params.append(risk_id)
    if control_id:
        query += " AND control_id = ?"
        params.append(control_id)
    query += " ORDER BY collected_at DESC LIMIT ?"
    params.append(limit)
    with db_session() as connection:
        rows = connection.execute(query, params).fetchall()
    items = []
    for row in rows:
        item = _row_dict(row)
        item["metadata"] = json.loads(item.pop("metadata_json"))
        items.append(item)
    return {"items": items, "count": len(items)}


@router.get("/compliance/summary")
def compliance_summary():
    with db_session() as connection:
        controls = connection.execute(
            "SELECT implementation_status, COUNT(*) AS count FROM controls GROUP BY implementation_status"
        ).fetchall()
        open_risks = connection.execute(
            "SELECT COUNT(*) AS count FROM risks WHERE status != 'closed'"
        ).fetchone()["count"]
        critical_risks = connection.execute(
            "SELECT COUNT(*) AS count FROM risks WHERE inherent_level = 'Critical' AND status != 'closed'"
        ).fetchone()["count"]
        evidence_count = connection.execute("SELECT COUNT(*) AS count FROM evidence").fetchone()["count"]

    status_counts = {row["implementation_status"]: row["count"] for row in controls}
    applicable = sum(count for status, count in status_counts.items() if status != "not_applicable")
    implemented = status_counts.get("implemented", 0)
    rate = round((implemented / applicable) * 100, 1) if applicable else 0.0
    return {
        "control_counts": status_counts,
        "applicable_controls": applicable,
        "implemented_controls": implemented,
        "implementation_rate_percent": rate,
        "open_risks": open_risks,
        "critical_open_risks": critical_risks,
        "evidence_records": evidence_count,
        "notice": "This is an internal implementation indicator, not a certification or a formal compliance attestation.",
    }


@router.post("/approvals", status_code=201)
def create_approval(payload: ApprovalCreate, x_actor: str = Header(default="unspecified")):
    data = _payload_dict(payload)
    approval_id = "APR-" + uuid.uuid4().hex[:12].upper()
    now = utc_now()
    with db_session() as connection:
        connection.execute(
            """
            INSERT INTO approvals (
                id, reference_type, reference_id, requested_action, requested_by,
                status, created_at
            ) VALUES (?, ?, ?, ?, ?, 'pending', ?)
            """,
            (approval_id, data["reference_type"], data["reference_id"], data["requested_action"], data["requested_by"], now),
        )
        row = connection.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        record_audit(connection, _audit_actor(x_actor), "approval.requested", "approval", approval_id, after=_row_dict(row))
    return _row_dict(row)


@router.patch("/approvals/{approval_id}/decision")
def decide_approval(approval_id: str, payload: ApprovalDecision, x_actor: str = Header(default="unspecified")):
    data = _payload_dict(payload)
    with db_session() as connection:
        row = connection.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Approval request not found")
        if row["status"] != "pending":
            raise HTTPException(status_code=409, detail="Approval request has already been decided")
        before = _row_dict(row)
        now = utc_now()
        connection.execute(
            """
            UPDATE approvals
            SET status = ?, decided_by = ?, decision_note = ?, decided_at = ?
            WHERE id = ? AND status = 'pending'
            """,
            (data["status"], data["decided_by"], data["decision_note"], now, approval_id),
        )
        after = _row_dict(connection.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone())
        record_audit(connection, _audit_actor(x_actor), "approval.decided", "approval", approval_id, before=before, after=after)
    return after


@router.get("/approvals")
def list_approvals(status: Optional[str] = Query(None), limit: int = Query(100, ge=1, le=500)):
    query = "SELECT * FROM approvals"
    params = []
    if status:
        query += " WHERE status = ?"
        params.append(status)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    with db_session() as connection:
        rows = connection.execute(query, params).fetchall()
    return {"items": [_row_dict(row) for row in rows], "count": len(rows)}


@router.post("/integrations/wazuh/evidence", status_code=201)
def record_wazuh_evidence(payload: WazuhEvidenceInput):
    data = _payload_dict(payload)
    if not data["risk_id"] and not data["control_ids"]:
        raise HTTPException(status_code=422, detail="Provide risk_id or at least one control_id")
    evidence_metadata = {
        "alert_id": data["alert_id"],
        "rule_id": data["rule_id"],
        "rule_level": data["rule_level"],
        "rule_description": data["rule_description"],
        "agent_id": data["agent_id"],
        "agent_name": data["agent_name"],
        "timestamp": data["timestamp"],
        "source_ip": data["source_ip"],
        "summary": data["summary"],
    }
    fingerprint = hashlib.sha256(
        json.dumps(evidence_metadata, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()

    created = []
    with db_session() as connection:
        if data["risk_id"] and _get_risk(connection, data["risk_id"]) is None:
            raise HTTPException(status_code=404, detail="Risk not found")
        for control_id in data["control_ids"]:
            if _get_control(connection, control_id) is None:
                raise HTTPException(status_code=404, detail=f"Control not found: {control_id}")
        targets = data["control_ids"] or [None]
        for control_id in targets:
            evidence_id = _insert_evidence(
                connection,
                risk_id=data["risk_id"],
                control_id=control_id,
                source="wazuh",
                reference_id=data["alert_id"],
                description=data["summary"],
                sha256=fingerprint,
                metadata=evidence_metadata,
                collected_by="wazuh-integration",
            )
            created.append(evidence_id)
    return {"status": "recorded", "source": "wazuh", "alert_id": data["alert_id"], "evidence_ids": created}


@router.post("/integrations/sham-ai/assessment", status_code=201)
def record_agent_assessment(payload: AgentAssessmentInput):
    data = _payload_dict(payload)
    if not data["risk_id"] and not data["control_ids"]:
        raise HTTPException(status_code=422, detail="Provide risk_id or at least one control_id")
    metadata = {
        "classification": data["classification"],
        "severity": data["severity"],
        "confidence": data["confidence"],
        "model_name": data["model_name"],
        "model_version": data["model_version"],
        "recommendations": data["recommendations"],
        "decision_authority": "recommendation_only_human_analyst_retains_final_decision",
    }
    fingerprint = hashlib.sha256(
        json.dumps(
            {"incident_id": data["incident_id"], "summary": data["summary"], **metadata},
            sort_keys=True,
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()

    created = []
    with db_session() as connection:
        if data["risk_id"] and _get_risk(connection, data["risk_id"]) is None:
            raise HTTPException(status_code=404, detail="Risk not found")
        for control_id in data["control_ids"]:
            if _get_control(connection, control_id) is None:
                raise HTTPException(status_code=404, detail=f"Control not found: {control_id}")
        targets = data["control_ids"] or [None]
        for control_id in targets:
            evidence_id = _insert_evidence(
                connection,
                risk_id=data["risk_id"],
                control_id=control_id,
                source="sham_ai",
                reference_id=data["incident_id"],
                description=data["summary"],
                sha256=fingerprint,
                metadata=metadata,
                collected_by="sham-ai-agent",
            )
            created.append(evidence_id)
    return {
        "status": "recorded",
        "source": "sham_ai",
        "incident_id": data["incident_id"],
        "evidence_ids": created,
        "decision_authority": "Human analyst retains final decision; this endpoint records AI recommendations only.",
    }


@router.get("/audit-logs")
def list_audit_logs(
    entity_type: Optional[str] = Query(None),
    entity_id: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
):
    query = "SELECT * FROM audit_logs WHERE 1 = 1"
    params = []
    if entity_type:
        query += " AND entity_type = ?"
        params.append(entity_type)
    if entity_id:
        query += " AND entity_id = ?"
        params.append(entity_id)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    with db_session() as connection:
        rows = connection.execute(query, params).fetchall()
    items = []
    for row in rows:
        item = _row_dict(row)
        for field in ("before_json", "after_json"):
            if item[field]:
                item[field.replace("_json", "")] = json.loads(item[field])
        items.append(item)
    return {"items": items, "count": len(items)}
