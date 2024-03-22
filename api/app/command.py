from typing import Sequence
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.sql.expression import func

from app import models


def get_pteam_tag_ids(db: Session, pteam_id: UUID | str) -> Sequence[str]:
    return db.scalars(
        select(models.PTeamTagReference.tag_id.distinct()).where(
            models.PTeamTagReference.pteam_id == str(pteam_id)
        )
    ).all()


def count_pteam_topics_per_threat_impact(
    db: Session,
    pteam_id: UUID | str,
    tag_id: UUID | str,
    is_solved: bool,
) -> dict[str, int]:
    threat_counts_rows = db.execute(
        select(
            models.CurrentPTeamTopicTagStatus.threat_impact,
            func.count(models.CurrentPTeamTopicTagStatus.threat_impact).label("num_rows"),
        )
        .where(
            models.CurrentPTeamTopicTagStatus.pteam_id == str(pteam_id),
            models.CurrentPTeamTopicTagStatus.tag_id == str(tag_id),
            (
                models.CurrentPTeamTopicTagStatus.topic_status == models.TopicStatusType.completed
                if is_solved
                else models.CurrentPTeamTopicTagStatus.topic_status
                != models.TopicStatusType.completed
            ),
        )
        .group_by(models.CurrentPTeamTopicTagStatus.threat_impact)
    ).all()
    return {
        "1": 0,
        "2": 0,
        "3": 0,
        "4": 0,
        **{str(row.threat_impact): row.num_rows for row in threat_counts_rows},
    }


def get_topic_ids_by_pteam_id_and_tag_id(
    db: Session,
    pteam_id: UUID | str,
    tag_id: UUID | str,
    is_solved: bool,
) -> Sequence[str]:
    _completed = models.TopicStatusType.completed
    return db.scalars(
        select(models.CurrentPTeamTopicTagStatus.topic_id)
        .where(
            models.CurrentPTeamTopicTagStatus.pteam_id == str(pteam_id),
            models.CurrentPTeamTopicTagStatus.tag_id == str(tag_id),
            (
                models.CurrentPTeamTopicTagStatus.topic_status == _completed
                if is_solved
                else models.CurrentPTeamTopicTagStatus.topic_status != _completed
            ),
        )
        .order_by(
            models.CurrentPTeamTopicTagStatus.threat_impact,
            models.CurrentPTeamTopicTagStatus.updated_at.desc(),
        )
    ).all()


def is_pteamtag(db: Session, pteam_id: UUID | str, tag_id: UUID | str) -> bool:
    return (
        db.execute(
            select(models.PTeamTagReference).where(
                models.PTeamTagReference.pteam_id == str(pteam_id),
                models.PTeamTagReference.tag_id == str(tag_id),
            )
        ).first()
        is not None
    )
