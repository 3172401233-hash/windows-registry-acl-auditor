"""测试用快照构造辅助。"""

from regacl.loader import snapshot_from_dict
from regacl.models import (
    SID_AUTHENTICATED_USERS,
    SID_BUILTIN_USERS,
    SID_INTERACTIVE,
    SID_LOCAL_SYSTEM,
    SID_TRUSTED_INSTALLER,
    SID_WORLD,
)

ALICE = "S-1-5-21-1111-2222-3333-1001"
BOB = "S-1-5-21-1111-2222-3333-1002"

USER_TOKEN_SIDS = [
    ALICE,
    SID_BUILTIN_USERS,
    SID_AUTHENTICATED_USERS,
    SID_INTERACTIVE,
    SID_WORLD,
]

SERVICES = "HKLM\\SYSTEM\\CurrentControlSet\\Services"


def ace(sid, mask, *, deny=False, flags=None, inherited=False, source=None):
    entry = {"sid": sid, "mask": mask}
    if deny:
        entry["type"] = "deny"
    if flags is not None:
        entry["flags"] = flags
    if inherited:
        entry["inherited"] = True
    if source is not None:
        entry["inherited_from"] = source
    return entry


def key(values=None, owner=SID_LOCAL_SYSTEM, dacl=(), control=None):
    data = {"security": {"owner": owner, "dacl": [] if dacl == () else dacl}}
    if values is not None:
        data["values"] = values
    if control is not None:
        data["security"]["control"] = control
    return data


def build(keys, *, token_sids=None, protected=None):
    data = {
        "token": {"sids": token_sids or USER_TOKEN_SIDS},
        "keys": keys,
    }
    if protected is not None:
        data["accounts"] = {"protected_sids": protected}
    else:
        data["accounts"] = {
            "protected_sids": [
                SID_LOCAL_SYSTEM,
                SID_TRUSTED_INSTALLER,
                "S-1-5-32-544",
                "S-1-5-80",
            ]
        }
    return snapshot_from_dict(data)


def service_path(name):
    return "%s\\%s" % (SERVICES, name)
