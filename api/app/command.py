from datetime import datetime
from typing import Sequence
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.sql.expression import and_, func

from app import models, persistence, schemas


def get_pteam_tag_ids(db: Session, pteam_id: UUID | str) -> Sequence[str]:
    return db.scalars(
        select(models.PTeamTagReference.tag_id.distinct()).where(
            models.PTeamTagReference.pteam_id == str(pteam_id)
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


def missing_pteam_admin(db: Session, pteam: models.PTeam) -> bool:
    return (
        db.execute(
            select(models.PTeamAuthority).where(
                models.PTeamAuthority.pteam_id == pteam.pteam_id,
                models.PTeamAuthority.authority.op("&")(models.PTeamAuthIntFlag.ADMIN) != 0,
            )
        ).first()
        is None
    )


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


def get_pteam_ext_tags(db: Session, pteam: models.PTeam) -> list[schemas.ExtTagResponse]:
    # TODO: should be moved to common
    # Note: this is temporal placement. following get_pteamtags_summary() requires me.

    tmp_dict: dict[tuple[str, str], schemas.ExtTagResponse] = {}
    ptrs = persistence.get_pteam_tag_references(db, pteam.pteam_id)
    for ptr in ptrs:
        key = (ptr.pteam_id, ptr.tag_id)
        tmp = tmp_dict.get(
            key,
            schemas.ExtTagResponse(
                tag_id=ptr.tag.tag_id,
                tag_name=ptr.tag.tag_name,
                parent_id=ptr.tag.parent_id,
                parent_name=ptr.tag.parent_name,
                references=[],
            ),
        )
        tmp.references.append({"group": ptr.group, "target": ptr.target, "version": ptr.version})
        tmp_dict[key] = tmp

    return sorted(tmp_dict.values(), key=lambda x: x.tag_name)


def get_pteamtags_summary(db: Session, pteam: models.PTeam) -> dict:
    # TODO: should be moved to common

    # get pteam ext tags
    ext_tags = get_pteam_ext_tags(db, pteam)

    # count statuses for each tags. Note: tags which has no topic does not appear
    _counts = (
        db.query(
            models.CurrentPTeamTopicTagStatus.tag_id,
            models.CurrentPTeamTopicTagStatus.topic_status,
            func.count(models.CurrentPTeamTopicTagStatus.topic_status).label("status_count"),
        )
        .filter(
            models.CurrentPTeamTopicTagStatus.pteam_id == pteam.pteam_id,
        )
        .group_by(
            models.CurrentPTeamTopicTagStatus.tag_id,
            models.CurrentPTeamTopicTagStatus.topic_status,
        )
        .all()
    )
    counts_map: dict[tuple[UUID, str], int] = {}
    for item in _counts:
        str_status = (item.topic_status or models.TopicStatusType.alerted).value
        counts_map[(UUID(item.tag_id), str_status)] = item.status_count

    # get min threat impact and max updated at
    _metas = db.execute(
        select(
            models.CurrentPTeamTopicTagStatus.tag_id,
            func.min(models.CurrentPTeamTopicTagStatus.threat_impact).label("threat_impact"),
            func.max(models.CurrentPTeamTopicTagStatus.updated_at).label("updated_at"),
        )
        .where(
            models.CurrentPTeamTopicTagStatus.pteam_id == pteam.pteam_id,
            models.CurrentPTeamTopicTagStatus.topic_status
            != models.TopicStatusType.completed.value,  # do not count completed
        )
        .group_by(
            models.CurrentPTeamTopicTagStatus.tag_id,
        )
    ).all()
    metas_map: dict[UUID, tuple[int, datetime | None]] = {}
    for _meta in _metas:
        metas_map[UUID(_meta.tag_id)] = (_meta.threat_impact or 4, _meta.updated_at)

    _status_count_keys = {
        models.TopicStatusType.alerted.value,
        models.TopicStatusType.acknowledged.value,
        models.TopicStatusType.scheduled.value,
        models.TopicStatusType.completed.value,
    }

    threat_impact_count = {"1": 0, "2": 0, "3": 0, "4": 0}
    summary_tags = []
    for ext_tag in ext_tags:
        threat_impact, updated_at = metas_map.get(ext_tag.tag_id, (None, None))
        status_count = {key: counts_map.get((ext_tag.tag_id, key), 0) for key in _status_count_keys}
        summary_tags.append(
            {
                **ext_tag.model_dump(),
                "status_count": status_count,
                "threat_impact": threat_impact,
                "updated_at": updated_at,
            }
        )
        threat_impact_count[str(threat_impact or 4)] += 1

    summary = {
        "threat_impact_count": threat_impact_count,
        "tags": sorted(
            summary_tags,
            key=lambda x: (
                x.get("threat_impact") or 4,
                -(_dt.timestamp() if (_dt := x.get("updated_at")) else 0),
                x.get("tag_name", ""),
            ),
        ),
    }

    return summary


def check_tag_is_related_to_topic(db: Session, tag: models.Tag, topic: models.Topic) -> bool:
    row = (
        db.query(models.Tag, models.TopicTag)
        .filter(models.Tag.tag_id == tag.tag_id)
        .outerjoin(
            models.TopicTag,
            and_(
                models.TopicTag.topic_id == topic.topic_id,
                models.TopicTag.tag_id.in_([models.Tag.tag_id, models.Tag.parent_id]),
            ),
        )
        .first()
    )
    return row is not None and row.TopicTag is not None


def get_last_updated_at_in_current_pteam_topic_tag_status(
    db: Session,
    pteam_id: UUID | str,
    tag_id: UUID | str,
) -> datetime | None:
    return db.scalars(
        select(func.max(models.CurrentPTeamTopicTagStatus.updated_at)).where(
            models.CurrentPTeamTopicTagStatus.pteam_id == str(pteam_id),
            models.CurrentPTeamTopicTagStatus.tag_id == str(tag_id),
            models.CurrentPTeamTopicTagStatus.topic_status != models.TopicStatusType.completed,
        )
    ).one()


def get_pteam_reference_versions_of_each_tags(
    db: Session,
    pteam_id: UUID | str,
) -> dict[str, set[str]]:  # {tag_id: {version, ...}}
    rows = db.execute(
        select(
            models.PTeamTagReference.tag_id,
            func.array_agg(models.PTeamTagReference.version).label("versions"),
        )
        .where(models.PTeamTagReference.pteam_id == str(pteam_id))
        .group_by(models.PTeamTagReference.tag_id)
    )
    return {row.tag_id: set(row.versions) for row in rows}
