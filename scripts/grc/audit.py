"""Append-only audit event helper."""

import json
import uuid
from typing import Any, Optional

from .db import utc_now


def record_audit(
    connection,
    actor: str,
    action: str,
    entity_type: str,
    entity_id: str,
    before: Optional[Any] = None,
    after: Optional[Any] = None,
    reason: Optional[str] = None,
) -> None:
    connection.execute(
        """
        INSERT INTO audit_logs (
            id, actor, action, entity_type, entity_id,
            before_json, after_json, reason, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            uuid.uuid4().hex,
            actor or "unspecified",
            action,
            entity_type,
            entity_id,
            json.dumps(before, ensure_ascii=False, default=str) if before is not None else None,
            json.dumps(after, ensure_ascii=False, default=str) if after is not None else None,
            reason,
            utc_now(),
        ),
    )
