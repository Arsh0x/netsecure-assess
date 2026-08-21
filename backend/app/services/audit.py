from sqlalchemy.orm import Session

from ..models import AuditLog, User


def record_audit(
    db: Session,
    action: str,
    user: User | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    details: dict | None = None,
    source_ip: str | None = None,
) -> AuditLog:
    log = AuditLog(
        user_id=user.id if user else None,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        details=details or {},
        source_ip=source_ip,
    )
    db.add(log)
    db.commit()
    return log

