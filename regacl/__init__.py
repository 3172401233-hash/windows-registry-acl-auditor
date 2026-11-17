"""windows-registry-acl-auditor：离线注册表 ACL 分析库。

本库只分析导出的注册表快照，不打开、不修改真实注册表。
"""

from .access import (
    AccessResult,
    Capability,
    evaluate,
)
from .analyzer import (
    AuditReport,
    Finding,
    audit,
    audit_path,
)
from .inheritance import effective_dacl
from .loader import Snapshot, load_reg_file, load_snapshot, parse_reg_text, snapshot_from_dict
from .models import (
    ACE,
    AccountSnapshot,
    RegistryKey,
    SecurityDescriptor,
    Token,
)
from .redirection import redirect_32bit, views_for
from .targets import classify, find_targets

__all__ = [
    "AccessResult",
    "ACE",
    "AccountSnapshot",
    "AuditReport",
    "Capability",
    "Finding",
    "RegistryKey",
    "SecurityDescriptor",
    "Snapshot",
    "Token",
    "audit",
    "audit_path",
    "classify",
    "effective_dacl",
    "evaluate",
    "find_targets",
    "load_reg_file",
    "load_snapshot",
    "parse_reg_text",
    "redirect_32bit",
    "snapshot_from_dict",
    "views_for",
]

__version__ = "1.0.0"
