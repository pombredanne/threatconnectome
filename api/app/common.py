import json
from datetime import datetime
from hashlib import md5
from typing import Dict, List, Optional, Sequence, Set, Tuple, Union
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import and_, delete, func, literal_column, or_, select
from sqlalchemy.dialects.postgresql import insert as psql_insert
from sqlalchemy.orm import Session
from sqlalchemy.sql.expression import false, true

from app import command, models, persistence, schemas
from app.constants import MEMBER_UUID, NOT_MEMBER_UUID, SYSTEM_UUID
from app.version import (
    PackageFamily,
    VulnerableRange,
    gen_version_instance,
)


def validate_tag(  # FIXME  remove after removing from tags.py
    db: Session,
    tag_id: Optional[Union[UUID, str]] = None,
    tag_name: Optional[str] = None,
    on_error: Optional[int] = None,
) -> Optional[models.Tag]:
    row = persistence.get_tag_by_tag_id_or_tag_name(db, tag_id, tag_name)
    if row is None and on_error is not None:
        raise HTTPException(status_code=on_error, detail="No such tag")
    return row


def check_tags_exist(db: Session, tag_names: List[str]):
    _existing_tags = (
        db.query(models.Tag.tag_name).filter(models.Tag.tag_name.in_(tag_names)).all()
    )  # [('tag1',), ('tag2',), ('tag3',)]
    existing_tag_names = set(tag_tuple[0] for tag_tuple in _existing_tags)
    not_existing_tag_names = set(tag_names) - existing_tag_names
    if len(not_existing_tag_names) >= 1:
        # TODO: set max length of not_exist_tag_names
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"No such tags: {', '.join(sorted(not_existing_tag_names))}",
        )


def validate_pteam(  # FIXME should obsolete
    db: Session,
    pteam_id: Union[UUID, str],
    on_error: Optional[int] = None,
    ignore_disabled: bool = False,
) -> Optional[models.PTeam]:
    pteam = (
        db.query(models.PTeam)
        .filter(
            models.PTeam.pteam_id == str(pteam_id),
            true() if ignore_disabled else models.PTeam.disabled.is_(False),
        )
        .one_or_none()
    )
    if pteam is None and on_error is not None:
        raise HTTPException(status_code=on_error, detail="No such pteam")
    return pteam


def check_pteam_membership(
    db: Session,
    pteam: models.PTeam | None,
    user: models.Account | None,
    ignore_ateam: bool = False,
) -> bool:
    if not pteam or not user:
        return False
    if user.user_id == str(SYSTEM_UUID):
        return True
    if user in pteam.members:
        return True
    if ignore_ateam:
        return False
    # check if a member of ateam which watches the pteam
    if any(user in ateam.members for ateam in pteam.ateams):
        return True
    return False


def check_pteam_auth(
    db: Session,
    pteam: models.PTeam,
    user: models.Account,
    required: models.PTeamAuthIntFlag,
) -> bool:
    if user.user_id == str(SYSTEM_UUID):
        return True

    user_auth = persistence.get_pteam_authority(db, pteam.pteam_id, user.user_id)
    int_auth = int(user_auth.authority) if user_auth else 0
    # append auth via pseudo-users
    if not_member_auth := persistence.get_pteam_authority(db, pteam.pteam_id, NOT_MEMBER_UUID):
        int_auth |= not_member_auth.authority
    if user in pteam.members and (
        member_auth := persistence.get_pteam_authority(db, pteam.pteam_id, MEMBER_UUID)
    ):
        int_auth |= member_auth.authority

    return int_auth & required == required


def check_ateam_membership(
    ateam: models.ATeam | None,
    user: models.Account | None,
) -> bool:
    if not ateam or not user:
        return False
    if user.user_id == str(SYSTEM_UUID):
        return True
    if user in ateam.members:
        return True
    return False


def check_ateam_auth(
    db: Session,
    ateam: models.ATeam,
    user: models.Account,
    required: models.ATeamAuthIntFlag,
) -> bool:
    if user.user_id == str(SYSTEM_UUID):
        return True

    user_auth = persistence.get_ateam_authority(db, ateam.ateam_id, user.user_id)
    int_auth = int(user_auth.authority) if user_auth else 0
    # append auth via pseudo-users
    if not_member_auth := persistence.get_ateam_authority(db, ateam.ateam_id, NOT_MEMBER_UUID):
        int_auth |= not_member_auth.authority
    if user in ateam.members and (
        member_auth := persistence.get_ateam_authority(db, ateam.ateam_id, MEMBER_UUID)
    ):
        int_auth |= member_auth.authority

    return int_auth & required == required


def get_tag_ids_with_parent_ids(tags: Sequence[models.Tag]) -> Sequence[str]:
    tag_ids_set: set[str] = set()
    for tag in tags:
        tag_ids_set.add(tag.tag_id)
        if tag.parent_id and tag.parent_id != tag.tag_id:
            tag_ids_set.add(tag.parent_id)
    return list(tag_ids_set)


def get_sorted_topics(topics: Sequence[models.Topic]) -> Sequence[models.Topic]:
    """
    Sort topics with standard sort rules -- (threat_impact ASC, updated_at DESC)
    """
    return sorted(
        topics,
        key=lambda topic: (
            topic.threat_impact,
            -(dt.timestamp() if (dt := topic.updated_at) else 0),
        ),
    )


def get_enabled_topics(topics: Sequence[models.Topic]) -> Sequence[models.Topic]:
    return list(filter(lambda t: t.disabled is False, topics))


def validate_topic(  # FIXME: should be removed
    db: Session,
    topic_id: Union[UUID, str],
    on_error: Optional[int] = None,
    ignore_disabled: bool = False,
) -> Optional[models.Topic]:
    topic = (
        db.query(models.Topic)
        .filter(
            models.Topic.topic_id == str(topic_id),
            true() if ignore_disabled else models.Topic.disabled.is_(False),
        )
        .one_or_none()
    )
    if topic is None and on_error is not None:
        raise HTTPException(status_code=on_error, detail="No such topic")
    return topic


def validate_action(  # FIXME: should be removed
    db: Session,
    action_id: Union[UUID, str],
    on_error: Optional[int] = None,
) -> Optional[models.TopicAction]:
    action = persistence.get_action(db, action_id)
    if action is None and on_error is not None:
        raise HTTPException(status_code=on_error, detail="No such topic action")
    return action


def check_topic_action_tags_integrity(
    topic_tags: Union[Sequence[str], Sequence[models.Tag]],  # tag_name list or topic.tags
    action_tags: Optional[List[str]],  # action.ext.get("tags")
    on_error: Optional[int] = None,  # FIXME: on_error should be obsoleted
) -> bool:
    if not action_tags:
        return True

    topic_tag_strs = {x if isinstance(x, str) else x.tag_name for x in topic_tags}
    for action_tag in action_tags:
        if action_tag not in topic_tag_strs and _pick_parent_tag(action_tag) not in topic_tag_strs:
            if on_error is None:
                return False
            raise HTTPException(
                status_code=on_error,
                detail="Action Tag mismatch with Topic Tag",
            )
    return True


def get_or_create_misp_tag(db: Session, tag_name: str) -> models.MispTag:
    if misp_tag := persistence.get_misp_tag_by_name(db, tag_name):
        return misp_tag

    misp_tag = models.MispTag(tag_name=tag_name)
    persistence.create_misp_tag(db, misp_tag)
    return misp_tag


def _pick_parent_tag(tag_name: str) -> Optional[str]:
    if len(tag_name.split(":", 2)) == 3:  # supported format
        return tag_name.rsplit(":", 1)[0] + ":"  # trim the right most field
    return None


def get_or_create_topic_tag(db: Session, tag_name: str) -> models.Tag:
    row = persistence.get_tag_by_name(db, tag_name)
    if row is not None:
        return row

    row = models.Tag(tag_name=tag_name, parent_id=None, parent_name=None)
    row = persistence.create_tag(db, row)
    db.commit()

    if parent_name := _pick_parent_tag(tag_name):
        parent_id = (
            row.tag_id
            if parent_name == tag_name
            else get_or_create_topic_tag(db, parent_name).tag_id
        )

        row.parent_name = parent_name
        row.parent_id = parent_id
        row = persistence.create_tag(db, row)
        db.commit()

    return row


def fix_current_status_by_pteam(db: Session, pteam: models.PTeam):
    if pteam.disabled:
        db.query(models.CurrentPTeamTopicTagStatus).filter(
            models.CurrentPTeamTopicTagStatus.pteam_id == pteam.pteam_id
        ).delete()
        db.commit()
        return

    # remove untagged
    db.execute(
        delete(models.CurrentPTeamTopicTagStatus).where(
            models.CurrentPTeamTopicTagStatus.pteam_id == pteam.pteam_id,
            models.CurrentPTeamTopicTagStatus.tag_id.not_in(
                select(models.PTeamTagReference.tag_id.distinct()).where(
                    models.PTeamTagReference.pteam_id == pteam.pteam_id
                )
            ),
        )
    )

    # insert missings or updated with latest
    tagged_topics = (
        db.query(models.TopicTag.topic_id, models.Tag.tag_id)  # tag_id is pteam tag (not topic tag)
        .join(
            models.Tag,
            and_(
                models.Tag.tag_id.in_(
                    select(models.PTeamTagReference.tag_id.distinct()).where(
                        models.PTeamTagReference.pteam_id == pteam.pteam_id
                    )
                ),
                or_(
                    models.TopicTag.tag_id == models.Tag.tag_id,
                    models.TopicTag.tag_id == models.Tag.parent_id,
                ),
            ),
        )
        .join(
            models.Topic,
            and_(
                models.Topic.topic_id == models.TopicTag.topic_id,
                models.Topic.disabled.is_(False),
            ),
        )
        .distinct()
        .subquery()
    )
    latests = (
        db.query(
            models.PTeamTopicTagStatus.pteam_id,
            models.PTeamTopicTagStatus.topic_id,
            models.PTeamTopicTagStatus.tag_id,
            func.max(models.PTeamTopicTagStatus.created_at).label("latest"),
        )
        .filter(
            models.PTeamTopicTagStatus.pteam_id == pteam.pteam_id,
        )
        .group_by(
            models.PTeamTopicTagStatus.pteam_id,
            models.PTeamTopicTagStatus.topic_id,
            models.PTeamTopicTagStatus.tag_id,
        )
        .subquery()
    )
    new_currents = (
        db.query(
            literal_column(f"'{pteam.pteam_id}'").label("pteam_id"),
            tagged_topics.c.topic_id,
            tagged_topics.c.tag_id,
            models.PTeamTopicTagStatus.status_id,
            func.coalesce(models.PTeamTopicTagStatus.topic_status, models.TopicStatusType.alerted),
            models.Topic.threat_impact,
            models.Topic.updated_at,
        )
        .join(
            models.Topic,
            models.Topic.topic_id == tagged_topics.c.topic_id,
        )
        .outerjoin(
            latests,
            and_(
                latests.c.pteam_id == pteam.pteam_id,
                latests.c.topic_id == tagged_topics.c.topic_id,
                latests.c.tag_id == tagged_topics.c.tag_id,
            ),
        )
        .outerjoin(
            models.PTeamTopicTagStatus,
            and_(
                models.PTeamTopicTagStatus.pteam_id == pteam.pteam_id,
                models.PTeamTopicTagStatus.topic_id == latests.c.topic_id,
                models.PTeamTopicTagStatus.tag_id == latests.c.tag_id,
                models.PTeamTopicTagStatus.created_at == latests.c.latest,  # use as uniq key
            ),
        )
    )
    insert_stmt = psql_insert(models.CurrentPTeamTopicTagStatus).from_select(
        [
            "pteam_id",
            "topic_id",
            "tag_id",
            "status_id",
            "topic_status",
            "threat_impact",
            "updated_at",
        ],
        new_currents,
    )
    db.execute(
        insert_stmt.on_conflict_do_update(
            index_elements=["pteam_id", "topic_id", "tag_id"],
            set_={
                "status_id": insert_stmt.excluded.status_id,
                "threat_impact": insert_stmt.excluded.threat_impact,
                "updated_at": insert_stmt.excluded.updated_at,
            },
        )
    )

    db.commit()


def fix_current_status_by_deleted_topic(db: Session, topic_id: Union[UUID, str]):
    db.query(models.CurrentPTeamTopicTagStatus).filter(
        models.CurrentPTeamTopicTagStatus.topic_id == str(topic_id)
    ).delete()
    db.commit()


def fix_current_status_by_topic(db: Session, topic: models.Topic):
    if topic.disabled:
        db.query(models.CurrentPTeamTopicTagStatus).filter(
            models.CurrentPTeamTopicTagStatus.topic_id == topic.topic_id
        ).delete()
        db.commit()
        return

    # remove untagged
    current_related_tags = (
        select(models.Tag.tag_id)
        .join(
            models.TopicTag,
            and_(
                models.TopicTag.topic_id == topic.topic_id,
                or_(
                    models.TopicTag.tag_id == models.Tag.tag_id,
                    models.TopicTag.tag_id == models.Tag.parent_id,
                ),
            ),
        )
        .distinct()
    )
    db.execute(
        delete(models.CurrentPTeamTopicTagStatus).where(
            models.CurrentPTeamTopicTagStatus.topic_id == topic.topic_id,
            models.CurrentPTeamTopicTagStatus.tag_id.not_in(current_related_tags),
        )
    )

    # fill missings or update -- at least updated_at is modified
    pteam_tags = (
        select(
            models.Tag.tag_id,
            models.PTeamTagReference.pteam_id,
        )
        .join(
            models.TopicTag,
            and_(
                models.TopicTag.topic_id == topic.topic_id,
                or_(
                    models.TopicTag.tag_id == models.Tag.tag_id,
                    models.TopicTag.tag_id == models.Tag.parent_id,
                ),
            ),
        )
        .join(
            models.PTeamTagReference,
            models.PTeamTagReference.tag_id == models.Tag.tag_id,
        )
        .join(
            models.PTeam,
            and_(
                models.PTeam.pteam_id == models.PTeamTagReference.pteam_id,
                models.PTeam.disabled.is_(False),
            ),
        )
        .distinct()
        .subquery()
    )
    latests = (
        select(
            models.PTeamTopicTagStatus.pteam_id,
            models.PTeamTopicTagStatus.topic_id,
            models.PTeamTopicTagStatus.tag_id,
            func.max(models.PTeamTopicTagStatus.created_at).label("latest"),
        )
        .where(
            models.PTeamTopicTagStatus.topic_id == topic.topic_id,
        )
        .group_by(
            models.PTeamTopicTagStatus.pteam_id,
            models.PTeamTopicTagStatus.topic_id,
            models.PTeamTopicTagStatus.tag_id,
        )
        .subquery()
    )
    new_currents = (
        select(
            pteam_tags.c.pteam_id,
            literal_column(f"'{topic.topic_id}'"),
            pteam_tags.c.tag_id,
            models.PTeamTopicTagStatus.status_id,
            func.coalesce(models.PTeamTopicTagStatus.topic_status, models.TopicStatusType.alerted),
            literal_column(f"'{topic.threat_impact}'"),
            literal_column(f"'{topic.updated_at}'"),
        )
        .outerjoin(
            latests,
            and_(
                latests.c.pteam_id == pteam_tags.c.pteam_id,
                latests.c.topic_id == topic.topic_id,
                latests.c.tag_id == pteam_tags.c.tag_id,
            ),
        )
        .outerjoin(
            models.PTeamTopicTagStatus,
            and_(
                models.PTeamTopicTagStatus.pteam_id == latests.c.pteam_id,
                models.PTeamTopicTagStatus.topic_id == topic.topic_id,
                models.PTeamTopicTagStatus.tag_id == latests.c.tag_id,
                models.PTeamTopicTagStatus.created_at == latests.c.latest,
            ),
        )
    )
    insert_stmt = psql_insert(models.CurrentPTeamTopicTagStatus).from_select(
        [
            "pteam_id",
            "topic_id",
            "tag_id",
            "status_id",
            "topic_status",
            "threat_impact",
            "updated_at",
        ],
        new_currents,
    )
    db.execute(
        insert_stmt.on_conflict_do_update(
            index_elements=["pteam_id", "topic_id", "tag_id"],
            set_={
                "status_id": insert_stmt.excluded.status_id,
                "threat_impact": insert_stmt.excluded.threat_impact,
                "updated_at": insert_stmt.excluded.updated_at,
            },
        )
    )

    db.commit()


def calculate_topic_content_fingerprint(
    title: str,
    abstract: str,
    threat_impact: int,
    tag_names: List[str],
) -> str:
    data = {
        "title": title,
        "abstract": abstract,
        "threat_impact": threat_impact,
        "tag_names": sorted(set(tag_names)),
    }
    return md5(json.dumps(data, sort_keys=True).encode()).hexdigest()


def get_pteam_topic_status_history(
    db: Session,
    status_id: Optional[Union[UUID, str]] = None,
    pteam_id: Optional[Union[UUID, str]] = None,
    topic_id: Optional[Union[UUID, str]] = None,
    tag_id: Optional[Union[UUID, str]] = None,
    topic_status: Optional[models.TopicStatusType] = None,
):
    rows = (
        db.query(models.PTeamTopicTagStatus, models.ActionLog)
        .filter(
            true() if status_id is None else models.PTeamTopicTagStatus.status_id == str(status_id),
            true() if pteam_id is None else models.PTeamTopicTagStatus.pteam_id == str(pteam_id),
            true() if topic_id is None else models.PTeamTopicTagStatus.topic_id == str(topic_id),
            true() if tag_id is None else models.PTeamTopicTagStatus.tag_id == str(tag_id),
            (
                true()
                if topic_status is None
                else models.PTeamTopicTagStatus.topic_status == topic_status
            ),
        )
        .outerjoin(
            models.ActionLog,
            func.array_position(
                models.PTeamTopicTagStatus.logging_ids, models.ActionLog.logging_id
            ).is_not(None),
        )
        .all()
    )

    ret_dict: Dict[str, schemas.TopicStatusResponse] = {}
    for topictagstatus, actionlog in rows:
        ret = ret_dict.get(
            topictagstatus.status_id,
            schemas.TopicStatusResponse(**topictagstatus.__dict__, action_logs=[]),
        )
        if actionlog is not None:
            ret.action_logs.append(schemas.ActionLogResponse(**actionlog.__dict__))
        ret_dict[topictagstatus.status_id] = ret
    for val in ret_dict.values():
        val.action_logs.sort(key=lambda x: x.executed_at, reverse=True)

    return sorted(ret_dict.values(), key=lambda x: x.created_at, reverse=True)


def set_pteam_topic_status_internal(
    db: Session,
    user: models.Account,
    pteam: models.PTeam,
    topic_id: Union[UUID, str],
    tag: models.Tag,  # should be PTeamTag, not TopicTag
    data: schemas.TopicStatusRequest,
) -> schemas.TopicStatusResponse | None:
    current_status = persistence.get_current_pteam_topic_tag_status(
        db, pteam.pteam_id, topic_id, tag.tag_id
    )
    new_status = models.PTeamTopicTagStatus(
        pteam_id=pteam.pteam_id,
        topic_id=str(topic_id),
        tag_id=tag.tag_id,
        topic_status=data.topic_status,
        user_id=user.user_id,
        note=data.note,
        logging_ids=list(set(data.logging_ids)),
        assignees=(
            [user.user_id]
            if (
                (
                    current_status is None
                    or current_status.topic_status == models.TopicStatusType.alerted
                )
                and data.assignees == []
                and data.topic_status == models.TopicStatusType.acknowledged
            )
            else list(set(data.assignees))
        ),
        scheduled_at=data.scheduled_at,
        created_at=datetime.now(),
    )
    new_status = persistence.create_pteam_topic_tag_status(db, new_status)

    if not current_status:
        current_status = persistence.create_current_pteam_topic_tag_status(
            db,
            models.CurrentPTeamTopicTagStatus(
                pteam_id=pteam.pteam_id,
                topic_id=str(topic_id),
                tag_id=tag.tag_id,
                status_id=None,  # fill later
                threat_impact=None,  # fill later
                updated_at=None,  # fill later
            ),
        )
    current_status.status_id = new_status.status_id
    current_status.topic_status = new_status.topic_status

    # FIXME!  topic should be given by arg
    topic = db.scalars(
        select(models.Topic).where(models.Topic.topic_id == str(topic_id))
    ).one_or_none()
    assert topic

    current_status.threat_impact = topic.threat_impact
    current_status.updated_at = (
        None if new_status.topic_status == models.TopicStatusType.completed else topic.updated_at
    )

    db.flush()

    return command.pteam_topic_tag_status_to_response(db, new_status)


def _pick_actions_related_to_pteamtag_from_topic(
    db: Session,
    topic: models.Topic,
    pteam: models.PTeam,
    tag: models.Tag,  # should be bound to pteam, not to topic
) -> Sequence[models.TopicAction]:
    select_stmt = select(models.TopicAction).where(
        models.TopicAction.topic_id == topic.topic_id,
        # Note:
        #   We should find INVALID or EMPTY vulnerables to abort auto-close, but could not. :(
        #   SQL will skip the row caused error, e.g. KeyError on JSON.
        #   Thus "WHERE NOT json_array_length(...) > 0" does not make sense.
        or_(
            func.json_array_length(  # len(ext["vulnerable_versions"][tag_name])
                models.TopicAction.ext.op("->")("vulnerable_versions").op("->")(tag.tag_name)
            )
            > 0,
            and_(
                true() if tag.tag_name != tag.parent_name else false(),
                func.json_array_length(
                    models.TopicAction.ext.op("->")("vulnerable_versions").op("->")(tag.parent_name)
                )
                > 0,
            ),
        ),
    )
    actions = db.scalars(select_stmt).all()
    return list(set(actions))


def _pick_vulnerable_version_strings_from_actions(
    actions: Sequence[models.TopicAction],
    tag: models.Tag,
) -> Set[str]:
    tag_name = tag.tag_name
    parent_name = tag.parent_name
    vulnerable_versions = set()
    for action in actions:
        vulnerable_versions |= set(action.ext.get("vulnerable_versions", {}).get(tag_name, []))
        if parent_name and parent_name != tag_name:
            vulnerable_versions |= set(
                action.ext.get("vulnerable_versions", {}).get(parent_name, [])
            )
    result: Set[str] = set()
    for vulnerable_version in vulnerable_versions:
        result |= set(vulnerable_version.split("||"))
    return result


def _complete_topic(
    db: Session,
    pteam: models.PTeam,
    tag: models.Tag,
    actions: Sequence[models.TopicAction],
):
    if not actions:
        return
    topic_id = actions[0].topic_id
    system_account = persistence.get_system_account(db)
    now = datetime.now()

    logging_ids = []
    for action in actions:
        action_log = models.ActionLog(
            action_id=action.action_id,
            topic_id=topic_id,
            action=action.action,
            action_type=action.action_type,
            recommended=action.recommended,
            user_id=system_account.user_id,
            pteam_id=pteam.pteam_id,
            email=system_account.email,
            executed_at=now,
            created_at=now,
        )
        persistence.create_action_log(db, action_log)
        logging_ids.append(action_log.logging_id)

    set_pteam_topic_status_internal(
        db,
        system_account,
        pteam,
        topic_id,
        tag,
        schemas.TopicStatusRequest(
            topic_status=models.TopicStatusType.completed,
            logging_ids=list(map(UUID, logging_ids)),
            note="auto closed by system",
        ),
    )


def pteamtag_try_auto_close_topic(
    db: Session,
    pteam: models.PTeam,
    tag: models.Tag,  # should be bound to pteam, not to topic
    topic: models.Topic,
):
    if topic.disabled or pteam.disabled:
        return

    try:
        # pick unique reference versions to compare. (omit empty -- maybe added on WebUI)
        reference_versions = db.scalars(
            select(models.PTeamTagReference.version.distinct()).where(
                models.PTeamTagReference.pteam_id == pteam.pteam_id,
                models.PTeamTagReference.tag_id == tag.tag_id,
                models.PTeamTagReference.version != "",
            )
        ).all()
        if not reference_versions:
            return  # no references to compare
        # pick all actions which matched on tags
        actions = _pick_actions_related_to_pteamtag_from_topic(db, topic, pteam, tag)
        if not actions:  # this topic does not have actions for this pteamtag
            return
        # pick all matched vulnerables from actions
        vulnerable_strings = _pick_vulnerable_version_strings_from_actions(actions, tag)
        if not vulnerable_strings:
            return

        package_family = PackageFamily.from_tag_name(tag.tag_name)
        vulnerables = {
            VulnerableRange.from_string(package_family, vulnerable_string)
            for vulnerable_string in vulnerable_strings
        }
        references = {
            gen_version_instance(package_family, reference_version)
            for reference_version in reference_versions
        }
        # detect vulnerable
        if any(vulnerable.detect_matched(references) for vulnerable in vulnerables):
            return  # found at least 1 vulnerable
    except ValueError:  # found invalid, ambiguous or uncomparable
        return  # human check required

    # This topic has actionable actions, but no actions left to carry out for this pteamtag.
    _complete_topic(db, pteam, tag, actions)


def _pick_topics_related_to_pteamtag(
    db: Session,
    pteam: models.PTeam,
    tag: models.Tag,
) -> Sequence[models.Topic]:
    now = datetime.now()
    already_completed_or_scheduled_stmt = (
        select(models.CurrentPTeamTopicTagStatus)
        .join(
            models.PTeamTopicTagStatus,
            and_(
                models.CurrentPTeamTopicTagStatus.pteam_id == pteam.pteam_id,
                models.CurrentPTeamTopicTagStatus.tag_id == tag.tag_id,
                models.CurrentPTeamTopicTagStatus.topic_id == models.Topic.topic_id,
                models.PTeamTopicTagStatus.status_id == models.CurrentPTeamTopicTagStatus.status_id,
                or_(
                    models.PTeamTopicTagStatus.topic_status == models.TopicStatusType.completed,
                    and_(
                        models.PTeamTopicTagStatus.topic_status == models.TopicStatusType.scheduled,
                        models.PTeamTopicTagStatus.scheduled_at > now,
                    ),
                ),
            ),
        )
        .exists()
    )
    select_topic_stmt = select(models.Topic).join(
        models.TopicTag,
        and_(
            models.Topic.disabled.is_(False),
            models.TopicTag.tag_id.in_([tag.tag_id, tag.parent_id]),
            models.TopicTag.topic_id == models.Topic.topic_id,
            ~already_completed_or_scheduled_stmt,
        ),
    )

    topics = db.scalars(select_topic_stmt).all()
    return topics


def auto_close_by_pteamtags(db: Session, pteamtags: List[Tuple[models.PTeam, models.Tag]]):
    for pteam, tag in pteamtags:
        if pteam.disabled:
            continue
        for topic in _pick_topics_related_to_pteamtag(db, pteam, tag):
            pteamtag_try_auto_close_topic(db, pteam, tag, topic)


def _pick_pteamtags_related_to_topic(
    db: Session,
    topic: models.Topic,
) -> Sequence[Tuple[models.PTeam, models.Tag]]:
    if topic.disabled:
        return []
    now = datetime.now()
    already_completed_or_scheduled_stmt = (
        select(models.CurrentPTeamTopicTagStatus)
        .join(
            models.PTeamTopicTagStatus,
            and_(
                models.CurrentPTeamTopicTagStatus.topic_id == topic.topic_id,
                models.PTeamTopicTagStatus.status_id == models.CurrentPTeamTopicTagStatus.status_id,
                or_(
                    models.PTeamTopicTagStatus.topic_status == models.TopicStatusType.completed,
                    and_(
                        models.PTeamTopicTagStatus.topic_status == models.TopicStatusType.scheduled,
                        models.PTeamTopicTagStatus.scheduled_at > now,
                    ),
                ),
            ),
        )
        .exists()
    )
    select_ptrs_related_to_topic_stmt = (
        select(
            models.PTeamTagReference.pteam_id,
            models.PTeamTagReference.tag_id,
            models.PTeam,
            models.Tag,
        )
        .distinct()
        .join(models.Tag)
        .join(
            models.TopicTag,
            and_(
                models.TopicTag.topic_id == topic.topic_id,
                or_(
                    models.TopicTag.tag_id == models.Tag.tag_id,
                    models.TopicTag.tag_id == models.Tag.parent_id,
                ),
                ~already_completed_or_scheduled_stmt,
            ),
        )
        .join(
            models.PTeam,
            and_(
                models.PTeam.disabled.is_(False),
                models.PTeamTagReference.pteam_id == models.PTeam.pteam_id,
            ),
        )
    )

    ptrs = db.execute(select_ptrs_related_to_topic_stmt).all()
    return [(ptr.PTeam, ptr.Tag) for ptr in ptrs]


def auto_close_by_topic(db: Session, topic: models.Topic):
    if topic.disabled:
        return
    for pteam, tag in _pick_pteamtags_related_to_topic(db, topic):
        pteamtag_try_auto_close_topic(db, pteam, tag, topic)
