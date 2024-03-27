import json
from datetime import datetime
from hashlib import md5
from typing import List, Optional, Sequence, Set, Tuple, Union
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session
from sqlalchemy.sql.expression import false, true

from app import command, models, persistence, schemas
from app.constants import MEMBER_UUID, NOT_MEMBER_UUID, SYSTEM_UUID
from app.version import (
    PackageFamily,
    VulnerableRange,
    gen_version_instance,
)


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


def _pick_parent_tag(tag_name: str) -> Optional[str]:
    if len(tag_name.split(":", 2)) == 3:  # supported format
        return tag_name.rsplit(":", 1)[0] + ":"  # trim the right most field
    return None


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


def get_or_create_topic_tag(db: Session, tag_name: str) -> models.Tag:
    if tag := persistence.get_tag_by_name(db, tag_name):  # already exists
        return tag

    tag = models.Tag(tag_name=tag_name, parent_id=None, parent_name=None)
    if not (parent_name := _pick_parent_tag(tag_name)):  # no parent: e.g. "tag1"
        persistence.create_tag(db, tag)
        return tag

    if parent_name == tag_name:  # parent is myself
        tag.parent_id = tag.tag_id
        tag.parent_name = tag_name
    else:
        parent = get_or_create_topic_tag(db, parent_name)
        tag.parent_id = parent.tag_id
        tag.parent_name = parent.tag_name

    persistence.create_tag(db, tag)

    return tag


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


def set_pteam_topic_status_internal(
    db: Session,
    current_user: models.Account,
    pteam: models.PTeam,
    topic: models.Topic,
    tag: models.Tag,  # should be PTeamTag, not TopicTag
    data: schemas.TopicStatusRequest,
) -> schemas.TopicStatusResponse | None:
    current_status = persistence.get_current_pteam_topic_tag_status(
        db, pteam.pteam_id, topic.topic_id, tag.tag_id
    )
    if (
        (not current_status or current_status.topic_status == models.TopicStatusType.alerted)
        and data.topic_status == models.TopicStatusType.acknowledged
        and not data.assignees  # first ack without assignees
    ):
        assignees = [current_user.user_id]  # force assign current_user
    else:
        assignees = list(map(str, data.assignees))
    new_status = models.PTeamTopicTagStatus(
        pteam_id=pteam.pteam_id,
        topic_id=topic.topic_id,
        tag_id=tag.tag_id,
        topic_status=data.topic_status,
        user_id=current_user.user_id,
        note=data.note,
        logging_ids=list(set(data.logging_ids)),
        assignees=list(set(assignees)),
        scheduled_at=data.scheduled_at,
        created_at=datetime.now(),
    )
    persistence.create_pteam_topic_tag_status(db, new_status)

    if not current_status:
        current_status = models.CurrentPTeamTopicTagStatus(
            pteam_id=pteam.pteam_id,
            topic_id=topic.topic_id,
            tag_id=tag.tag_id,
            status_id=None,  # fill later
            topic_status=None,  # fill later
            threat_impact=None,  # fill later
            updated_at=None,  # fill later
        )
        persistence.create_current_pteam_topic_tag_status(db, current_status)

    current_status.status_id = new_status.status_id
    current_status.topic_status = new_status.topic_status
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

    topic = actions[0].topic
    system_account = persistence.get_system_account(db)
    now = datetime.now()

    logging_ids = []
    for action in actions:
        action_log = models.ActionLog(
            action_id=action.action_id,
            topic_id=topic.topic_id,
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
        topic,
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
