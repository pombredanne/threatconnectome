from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import models, persistence, schemas
from app.auth import get_current_user
from app.common import (
    check_pteam_membership,
    create_actionlog_internal,
    validate_topic,
)
from app.database import get_db
from app.models import ActionType

router = APIRouter(prefix="/actionlogs", tags=["actionlogs"])


@router.get("", response_model=List[schemas.ActionLogResponse])
def get_logs(
    current_user: models.Account = Depends(get_current_user), db: Session = Depends(get_db)
):
    """
    Get actionlogs of pteams the user belongs to.
    """
    logs = persistence.get_action_logs(db, current_user.user_id)
    result = []
    for log in logs:
        if log.created_at:
            log.created_at = log.created_at.astimezone(timezone.utc)
        if log.executed_at:
            log.executed_at = log.executed_at.astimezone(timezone.utc)
        result.append(log.__dict__)
    return result


@router.post("", response_model=schemas.ActionLogResponse)
def create_log(
    data: schemas.ActionLogRequest,
    current_user: models.Account = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Add an action log to the topic.

    `executed_at` is optional, the default is the current time in the server.

    The format of `executed_at` is ISO-8601.
    In linux, you can check it with `date --iso-8601=seconds`.
    """
    return create_actionlog_internal(data, current_user, db)


@router.get("/search", response_model=List[schemas.ActionLogResponse])
def search_logs(
    topic_ids: Optional[List[UUID]] = Query(None),
    action_words: Optional[List[str]] = Query(None),
    action_types: Optional[List[ActionType]] = Query(None),
    user_ids: Optional[List[UUID]] = Query(None),
    pteam_ids: Optional[List[UUID]] = Query(None),
    emails: Optional[List[str]] = Query(None),
    executed_before: Optional[datetime] = Query(None),
    executed_after: Optional[datetime] = Query(None),
    created_before: Optional[datetime] = Query(None),
    created_after: Optional[datetime] = Query(None),
    current_user: models.Account = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Search actionlogs.
    """
    if pteam_ids is None:
        pteam_ids = [pteam.pteam_id for pteam in current_user.pteams]
    else:
        for pteam_id in pteam_ids:
            pteam = db.scalars(
                select(models.PTeam).where(models.PTeam.pteam_id == pteam_id)
            ).one_or_none()
            check_pteam_membership(db, pteam, current_user)
    rows = persistence.search_logs(
        db,
        topic_ids,
        action_words,
        action_types,
        user_ids,
        pteam_ids,
        emails,
        executed_before,
        executed_after,
        created_before,
        created_after,
    )
    return sorted(rows, key=lambda x: x.executed_at, reverse=True)


@router.get("/topics/{topic_id}", response_model=List[schemas.ActionLogResponse])
def get_topic_logs(
    topic_id: UUID,
    current_user: models.Account = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Get actionlogs associated with the specified topic.
    """
    topic = validate_topic(db, topic_id, on_error=status.HTTP_404_NOT_FOUND)
    assert topic
    rows = persistence.get_topic_logs(db, topic_id, current_user.user_id)
    return sorted(rows, key=lambda x: x.executed_at, reverse=True)
