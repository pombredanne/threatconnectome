from uuid import uuid4

USER1 = {  # see firebase/data-test/auth_export/accounts.json
    "email": "test1@example.com",
    "pass": "testpass1",  # see tail of passwordHash on accounts.json
    "disabled": False,
    "years": 2,
}
USER2 = {
    "email": "test2@example.com",
    "pass": "testpass2",
    "uid": "2UZpJaGjHjm8DPTv8I60sxLxqye8",
    "disabled": False,
    "years": 5,
}
USER3 = {
    "email": "test3@example.com",
    "pass": "testpass3",
    "uid": "Bh2Ed1qXyg5Gv362oMk9YXwdpiME",
    "disabled": False,
    "years": 2,
}
TAG1 = "alpha:alpha2:alpha3"
TAG2 = "bravo:bravo2:bravo3"
TAG3 = "charlie:charlie2:charlie3"
SERVICE1 = "Threatconnectome"
SERVICE2 = "RepoA"
REF1 = [
    {"target": "api/Pipfile.lock", "version": "1.0.0", "service": "Threatconnectome"},
    {"target": "api2/Pipfile.lock", "version": "1.0.1", "service": "Threatconnectome"},
    {"target": "api/Pipfile.lock", "version": "1.0.0", "service": "Flashsense"},
]
REF2 = [{"target": "web/package-lock.json", "version": "1.1.1", "service": "RepoA"}]
REF3 = [
    {
        "target": "Pipfile.lock",
        "version": "a1daed12b7955ab3ca423f7242a9ccfd249f2ebcba180a9376aea74b1ec913d0",
        "service": "productB",
    }
]

MISPTAG1 = "tlp:amber"
MISPTAG2 = "tlp:clear"
MISPTAG3 = "tlp:red"
PTEAM1 = {
    "pteam_name": "pteam alpha",
    "contact_info": "alpha@ml.com",
    "alert_slack": {"enable": True, "webhook_url": ""},
    "alert_ssvc_priority": "scheduled",
    "alert_mail": {"enable": False, "address": "alpha@ml.com"},  # disable SendGrid if not needed
}

PTEAM2 = {
    "pteam_name": "pteam bravo",
    "contact_info": "bravo@ml.com",
    "alert_slack": {"enable": True, "webhook_url": ""},
    "alert_ssvc_priority": "out_of_cycle",
    "alert_mail": {"enable": False, "address": "bravo@ml.com"},  # disable SendGrid if not needed
}
TOPIC1 = {
    "topic_id": uuid4(),
    "title": "topic one",
    "abstract": "abstract one",
    "tags": [TAG1],
    "misp_tags": [MISPTAG1],
    "actions": [],
    "exploitation": "active",
    "automatable": "yes",
    "cvss_v3_score": 2.0,
    "cve_id": "CVE-0000-0001",
}
TOPIC2 = {
    "topic_id": uuid4(),
    "title": "topic two",
    "abstract": "abstract two",
    "tags": [TAG1],
    "misp_tags": [],
    "actions": [],
    "exploitation": "active",
    "automatable": "yes",
}
TOPIC3 = {
    "topic_id": uuid4(),
    "title": "topic three",
    "abstract": "abstract three",
    "tags": [TAG1, TAG3],
    "misp_tags": [],
    "actions": [],
    "exploitation": "active",
    "automatable": "yes",
}
TOPIC4 = {
    "topic_id": uuid4(),
    "title": "topic four",
    "abstract": "abstract four",
    "tags": [TAG3],
    "misp_tags": [],
    "actions": [],
    "exploitation": "active",
    "automatable": "yes",
}
ACTION1 = {
    "action": "action one",
    "action_type": "elimination",
    "recommended": True,
    "ext": {},
}
ACTION2 = {
    "action": "action two",
    "action_type": "mitigation",
    "recommended": False,
    "ext": {},
}
ACTION3 = {
    "action": "action three",
    "action_type": "rejection",
    "recommended": False,
    "ext": {},
}

SAMPLE_SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/T00000000/B00000000/XXXX"
