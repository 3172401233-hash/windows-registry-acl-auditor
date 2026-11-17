"""注册表 ACL 分析主入口。

对快照中的高价值目标逐键（含 WOW64 视图）计算普通用户的有效权限，
输出能控制服务/启动执行的关键键与具体权限，并标注命中的 ACE 来源，
区分普通用户与受保护进程账户。
"""

from dataclasses import dataclass, field, asdict

from . import rights
from .access import (
    WRITE_CAPABILITIES,
    evaluate,
    explain_access,
)
from .redirection import views_for
from .targets import find_targets

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"


@dataclass
class Finding:
    """单个可利用键的审计结论。"""

    path: str
    view: str
    physical_path: str
    category: str
    severity: str
    granted_capabilities: list[str]
    controlled_values: list[str]
    detail: str
    owner: str | None
    null_dacl: bool
    protected_dacl: bool
    inherited_blocked_by: str | None
    granted_mask: int
    granting_aces: list[dict]
    protected_account_aces: list[dict]

    def to_dict(self):
        return asdict(self)


@dataclass
class AuditReport:
    findings: list[Finding] = field(default_factory=list)
    read_only_targets: list[dict] = field(default_factory=list)
    scanned_targets: int = 0

    @property
    def critical_keys(self):
        return [
            item
            for item in self.findings
            if item.severity == SEVERITY_CRITICAL
        ]

    def to_dict(self):
        return {
            "findings": [item.to_dict() for item in self.findings],
            "read_only_targets": self.read_only_targets,
            "scanned_targets": self.scanned_targets,
        }


def _ace_record(ace, accounts):
    return {
        "decision": "deny" if ace.is_deny else "allow",
        "sid": ace.trustee,
        "name": accounts.display_name(ace.trustee),
        "mask": "0x%08X" % ace.access_mask,
        "rights": rights.mask_to_names(ace.access_mask),
        "inherited": ace.inherited,
        "inherited_from": ace.inherited_from,
        "protected_account": accounts.is_protected_sid(ace.trustee),
    }


def _severity_for(target, capabilities):
    if target.category in ("service", "service_root"):
        if "write_value" in capabilities or "create_subkey" in capabilities:
            return SEVERITY_CRITICAL
        return SEVERITY_HIGH
    if target.category in ("startup", "shell_command", "file_association"):
        if "write_value" in capabilities or "create_subkey" in capabilities:
            return SEVERITY_HIGH
        return SEVERITY_MEDIUM
    return SEVERITY_MEDIUM


def audit(snapshot, *, include_read_only=True):
    """对快照执行完整审计，返回 :class:`AuditReport`。"""
    report = AuditReport()
    targets = find_targets(snapshot.keys)
    report.scanned_targets = len(targets)

    audited_views = set()

    for target in targets:
        for view_name, logical_path, physical_path in views_for(target.path):
            view_key = (view_name, physical_path)
            if view_key in audited_views:
                continue
            audited_views.add(view_key)

            if physical_path not in snapshot.keys:
                continue

            result = evaluate(
                snapshot.keys, physical_path, snapshot.token
            )
            granted = [
                name
                for name in WRITE_CAPABILITIES
                if result.has(name)
            ]

            ace_records = [
                _ace_record(ace, snapshot.accounts)
                for ace in result.effective_dacl.aces
                if snapshot.token.contains_sid(ace.trustee)
            ]
            protected_records = [
                _ace_record(ace, snapshot.accounts)
                for ace in result.effective_dacl.aces
                if not snapshot.token.contains_sid(ace.trustee)
                and snapshot.accounts.is_protected_sid(ace.trustee)
            ]

            if not granted:
                if include_read_only:
                    report.read_only_targets.append(
                        {
                            "path": logical_path,
                            "physical_path": physical_path,
                            "view": view_name,
                            "category": target.category,
                            "granted_rights": rights.mask_to_names(
                                result.granted_mask
                            ),
                            "denied_rights": rights.mask_to_names(
                                result.denied_mask
                            ),
                        }
                    )
                continue

            report.findings.append(
                Finding(
                    path=logical_path,
                    view=view_name,
                    physical_path=physical_path,
                    category=target.category,
                    severity=_severity_for(target, granted),
                    granted_capabilities=granted,
                    controlled_values=sorted(target.controlled_values),
                    detail=target.detail,
                    owner=result.effective_dacl.owner,
                    null_dacl=result.null_dacl,
                    protected_dacl=result.effective_dacl.protected,
                    inherited_blocked_by=result.effective_dacl.inherited_blocked_by,
                    granted_mask=result.granted_mask,
                    granting_aces=ace_records,
                    protected_account_aces=protected_records,
                )
            )

    report.findings.sort(
        key=lambda item: (
            {"critical": 0, "high": 1, "medium": 2}[item.severity],
            item.category,
            item.path,
        )
    )
    return report


def audit_path(snapshot, path):
    """不经过目标分类，直接审计任意键（含两个 WOW64 视图）。"""
    results = []
    for view_name, logical_path, physical_path in views_for(path):
        if physical_path not in snapshot.keys:
            continue
        result = evaluate(snapshot.keys, physical_path, snapshot.token)
        results.append(
            {
                "view": view_name,
                "logical_path": logical_path,
                "physical_path": physical_path,
                "granted_mask": "0x%08X" % result.granted_mask,
                "granted_rights": rights.mask_to_names(result.granted_mask),
                "capabilities": {
                    name: capability.granted
                    for name, capability in result.capabilities.items()
                },
                "aces": explain_access(result, snapshot.accounts),
            }
        )
    return results
