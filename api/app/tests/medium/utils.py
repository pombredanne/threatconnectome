import json
import random
import string
import tempfile
from datetime import datetime
from typing import Dict, List, Optional, Sequence, Tuple, Union
from uuid import UUID

from fastapi.testclient import TestClient

from app import models, schemas
from app.main import app
from app.tests.medium.exceptions import HTTPError
from app.tests.medium.routers.test_auth import get_access_token_headers, get_file_upload_headers

client = TestClient(app)


def to_datetime(datetime_value: datetime | str | None) -> datetime | None:
    if datetime_value is None:
        return None
    if isinstance(datetime_value, datetime):
        return datetime_value
    return datetime.fromisoformat(datetime_value)


def assert_200(response) -> dict:
    if response.status_code != 200:
        raise HTTPError(response)
    return response.json()


def assert_204(response):
    if response.status_code != 204:
        raise HTTPError(response)


def schema_to_dict(data) -> dict:
    if isinstance(data, schemas.TagResponse):
        return {
            "tag_name": data.tag_name,
            "tag_id": str(data.tag_id),
            "parent_name": data.parent_name,
            "parent_id": str(data.parent_id) if data.parent_id else None,
        }
    raise ValueError(f"Not implemented for {type(data)}")


def headers(user: dict) -> dict:
    return get_access_token_headers(user["email"], user["pass"])


def file_upload_headers(user: dict) -> dict:
    return get_file_upload_headers(user["email"], user["pass"])


def random_string(number: int) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=number))


def create_user(user: dict) -> schemas.UserResponse:
    request = {**user}
    del request["email"]
    del request["pass"]

    response = client.post("/users", headers=headers(user), json=request)

    if response.status_code != 200:
        raise HTTPError(response)
    return schemas.UserResponse(**response.json())


def create_pteam(user: dict, pteam: dict) -> schemas.PTeamInfo:
    request = {**pteam}

    response = client.post("/pteams", headers=headers(user), json=request)

    if response.status_code != 200:
        raise HTTPError(response)
    return schemas.PTeamInfo(**response.json())


def invite_to_pteam(
    user: dict,
    pteam_id: Union[UUID, str],
    auth: Optional[List[models.PTeamAuthEnum]] = None,
) -> schemas.PTeamInvitationResponse:
    request = {
        "expiration": str(datetime(3000, 1, 1, 0, 0, 0, 0)),
        "limit_count": 1,
        "authorities": auth,
    }

    response = client.post(f"/pteams/{pteam_id}/invitation", headers=headers(user), json=request)

    if response.status_code != 200:
        raise HTTPError(response)
    return schemas.PTeamInvitationResponse(**response.json())


def accept_pteam_invitation(user: dict, invitation_id: UUID) -> schemas.PTeamInfo:
    request = {
        "invitation_id": str(invitation_id),
    }

    response = client.post("/pteams/apply_invitation", headers=headers(user), json=request)

    if response.status_code != 200:
        raise HTTPError(response)
    return schemas.PTeamInfo(**response.json())


def upload_pteam_tags(
    user: dict,
    pteam_id: UUID | str,
    group: str,
    ext_tags: Dict[str, List[Tuple[str, str]]],  # {tag: [(target, version), ...]}
    force_mode: bool = True,
) -> List[schemas.ExtTagResponse]:
    params = {"group": group, "force_mode": str(force_mode)}
    with tempfile.NamedTemporaryFile(mode="w+t", suffix=".jsonl") as tfile:
        for tag_name, etags in ext_tags.items():
            assert all(len(etag) == 2 and None not in etag for etag in etags)  # check test code
            refs = [{"target": etag[0], "version": etag[1]} for etag in etags]
            tfile.writelines(json.dumps({"tag_name": tag_name, "references": refs}) + "\n")
        tfile.flush()
        with open(tfile.name, "rb") as bfile:
            data = assert_200(
                client.post(
                    f"/pteams/{pteam_id}/upload_tags_file",
                    headers=file_upload_headers(user),
                    params=params,
                    files={"file": bfile},
                )
            )
    return [schemas.ExtTagResponse(**item) for item in data]


def get_pteam_tags(user: dict, pteam_id: str) -> List[schemas.ExtTagResponse]:
    data = assert_200(client.get(f"/pteams/{pteam_id}/tags", headers=headers(user)))
    return [schemas.ExtTagResponse(**item) for item in data]


def get_pteam_groups(user: dict, pteam_id: str) -> schemas.PTeamGroupResponse:
    data = assert_200(client.get(f"/pteams/{pteam_id}/groups", headers=headers(user)))
    return schemas.PTeamGroupResponse(**data)


def create_ateam(user: dict, ateam: dict) -> schemas.ATeamInfo:
    request = {**ateam}

    response = client.post("/ateams", headers=headers(user), json=request)

    if response.status_code != 200:
        raise HTTPError(response)
    return schemas.ATeamInfo(**response.json())


def invite_to_ateam(
    user: dict,
    ateam_id: Union[UUID, str],
    authes: Optional[List[models.ATeamAuthEnum]] = None,
) -> schemas.ATeamInvitationResponse:
    request = {
        "expiration": str(datetime(3000, 1, 1, 0, 0, 0, 0)),
        "limit_count": 1,
        "authorities": authes,
    }

    response = client.post(f"/ateams/{ateam_id}/invitation", headers=headers(user), json=request)

    if response.status_code != 200:
        raise HTTPError(response)
    return schemas.ATeamInvitationResponse(**response.json())


def create_watching_request(
    user: dict,
    ateam_id: Union[UUID, str],
) -> schemas.ATeamWatchingRequestResponse:
    request = {
        "expiration": str(datetime(3000, 1, 1, 0, 0, 0, 0)),
        "limit_count": 1,
    }

    response = client.post(
        f"/ateams/{ateam_id}/watching_request", headers=headers(user), json=request
    )

    if response.status_code != 200:
        raise HTTPError(response)
    return schemas.ATeamWatchingRequestResponse(**response.json())


def accept_watching_request(user: dict, request_id: UUID, pteam_id: UUID) -> schemas.PTeamInfo:
    request = {
        "request_id": str(request_id),
        "pteam_id": str(pteam_id),
    }

    response = client.post("/ateams/apply_watching_request", headers=headers(user), json=request)

    if response.status_code != 200:
        raise HTTPError(response)
    return schemas.PTeamInfo(**response.json())


def accept_ateam_invitation(user: dict, invitation_id: UUID) -> schemas.ATeamInfo:
    request = {
        "invitation_id": str(invitation_id),
    }

    response = client.post("/ateams/apply_invitation", headers=headers(user), json=request)

    if response.status_code != 200:
        raise HTTPError(response)
    return schemas.ATeamInfo(**response.json())


def create_tag(user: dict, tag_name: str) -> schemas.TagResponse:
    request = {
        "tag_name": tag_name,
    }
    response = client.post("/tags", headers=headers(user), json=request)
    if response.status_code != 200:
        raise HTTPError(response)
    return schemas.TagResponse(**response.json())


def create_misp_tag(user: dict, tag_name: str) -> schemas.MispTagResponse:
    request = {
        "tag_name": tag_name,
    }
    response = client.post("/misp_tags", headers=headers(user), json=request)
    if response.status_code != 200:
        raise HTTPError(response)
    return schemas.MispTagResponse(**response.json())


def create_topic(
    user: dict,
    topic: dict,
    actions: Optional[List[dict]] = None,
    auto_create_tags: bool = True,
) -> schemas.TopicCreateResponse:
    request = {**topic}
    if actions is not None:
        request.update({"actions": actions})
    del request["topic_id"]

    response = client.post(f'/topics/{topic["topic_id"]}', headers=headers(user), json=request)

    if response.status_code != 200:
        no_tag_msg = "No such tags: "
        if (
            auto_create_tags
            and response.status_code == 400
            and (detail := response.json().get("detail", "")).startswith(no_tag_msg)
        ):
            for tag_name in detail[len(no_tag_msg) :].split(", "):  # split tag_names CSV
                create_tag(user, tag_name)
            return create_topic(user, topic, actions, auto_create_tags=False)
        raise HTTPError(response)
    return schemas.TopicCreateResponse(**response.json())


def update_topic(
    user: dict,
    topic: schemas.TopicEntry,
    params: dict,
) -> schemas.TopicResponse:
    data = assert_200(client.put(f"/topics/{topic.topic_id}", headers=headers(user), json=params))
    return schemas.TopicResponse(**data)


def search_topics(
    user: dict,
    params: dict,
) -> schemas.SearchTopicsResponse:
    data = assert_200(client.get("/topics/search", headers=headers(user), params=params))
    return schemas.SearchTopicsResponse(**data)


def create_action(
    user: dict,
    action: dict,
    topic_id: Union[str, UUID],
    ext: Optional[dict] = None,
) -> schemas.ActionResponse:
    request: dict = {**action, "topic_id": str(topic_id)}
    if ext is not None:
        request.update({"ext": ext})
    data = assert_200(client.post("/actions", headers=headers(user), json=request))
    return schemas.ActionResponse(**data)


def create_actionlog(
    user: dict,
    action_id: UUID,
    topic_id: UUID,
    user_id: UUID,
    pteam_id: UUID,
    executed_at: Optional[datetime],
) -> schemas.ActionLogResponse:
    request = {
        "action_id": str(action_id),
        "topic_id": str(topic_id),
        "user_id": str(user_id),
        "pteam_id": str(pteam_id),
        "executed_at": str(executed_at) if executed_at else None,
    }

    response = client.post("/actionlogs", headers=headers(user), json=request)

    if response.status_code != 200:
        raise HTTPError(response)
    return schemas.ActionLogResponse(**response.json())


def compare_tags(
    tags1: Sequence[dict | schemas.TagResponse],
    tags2: Sequence[dict | schemas.TagResponse],
) -> bool:
    def _to_tuple(tag_: dict | schemas.TagResponse):
        if isinstance(tag_, schemas.TagResponse):
            tag_ = tag_.model_dump()
        return (
            tag_.get("tag_name"),
            str(tag_.get("tag_id")),
            tag_.get("parent_name"),
            str(parent_id) if (parent_id := tag_.get("parent_id")) else None,
        )

    return [_to_tuple(t1) for t1 in tags1] == [_to_tuple(t2) for t2 in tags2]


def compare_references(refs1: List[dict], refs2: List[dict]) -> bool:
    def _to_tuple_set(refs):
        return {(ref.get("group"), ref.get("target"), ref.get("version")) for ref in refs}

    if not isinstance(refs1, list) or not isinstance(refs2, list):
        return False
    if len(refs1) != len(refs2):
        return False
    return _to_tuple_set(refs1) == _to_tuple_set(refs2)


def create_topicstatus(
    user: dict, pteam_id: UUID, topic_id: UUID, tag_id: UUID, json: dict
) -> schemas.TopicStatusResponse:
    response = assert_200(
        client.post(
            f"/pteams/{pteam_id}/topicstatus/{topic_id}/{tag_id}",
            headers=headers(user),
            json=json,
        )
    )
    return schemas.TopicStatusResponse(**response)


def common_put(user: dict, api_path: str, **kwargs) -> dict:
    response = client.put(api_path, headers=headers(user), json=kwargs)
    if response.status_code != 200:
        raise HTTPError(response)
    return response.json()
