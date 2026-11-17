"""有效访问权限计算（Windows AccessCheck 离线等价实现）。

规则：

* NULL DACL -> 所有人拥有 ``KEY_ALL_ACCESS``；
* 空 DACL -> 任何人无访问权；
* 按规范顺序遍历与令牌 SID 匹配的 ACE，拒绝项先于允许项累积；
* 键所有者隐式持有 ``READ_CONTROL | WRITE_DAC``（可重新写回 DACL）；
* 最终把权限位翻译成写值、改权限、删除子键等审计能力。
"""

from dataclasses import dataclass, field

from . import rights
from .models import Token


@dataclass(frozen=True)
class Capability:
    """单个审计能力的判定结果。"""

    name: str
    description: str
    granted: bool
    rights_needed: int


@dataclass
class AccessResult:
    """目标键针对某个令牌的完整访问判定。"""

    path: str
    granted_mask: int
    denied_mask: int
    null_dacl: bool
    is_owner: bool
    effective_dacl: EffectiveDacl
    capabilities: dict[str, Capability] = field(default_factory=dict)

    def has(self, capability_name):
        capability = self.capabilities.get(capability_name)
        return bool(capability and capability.granted)

    @property
    def writable(self):
        """是否具备任意可改变键/值/安全状态的写类能力。"""
        return any(
            capability.granted
            for name, capability in self.capabilities.items()
            if name != "read"
        )


# 审计能力 -> 所需 Windows 权限位
CAPABILITY_DEFINITIONS = {
    "write_value": (
        "写入/修改键值（如篡改 ImagePath、命令行）",
        rights.KEY_SET_VALUE,
    ),
    "create_subkey": (
        "创建子键（新增服务、Run 项或类注册）",
        rights.KEY_CREATE_SUB_KEY,
    ),
    "delete_subkey": (
        "删除键或子键（移除/替换服务注册）",
        rights.DELETE,
    ),
    "change_permissions": (
        "修改 DACL（WRITE_DAC，可给自己追加写权限）",
        rights.WRITE_DAC,
    ),
    "take_ownership": (
        "夺取所有权（WRITE_OWNER，随后可重写 DACL）",
        rights.WRITE_OWNER,
    ),
    "read": (
        "读取键值与枚举子键",
        rights.KEY_QUERY_VALUE | rights.KEY_ENUMERATE_SUB_KEYS,
    ),
}

# 可直接导致服务/启动执行被控制的高危能力
WRITE_CAPABILITIES = (
    "write_value",
    "create_subkey",
    "delete_subkey",
    "change_permissions",
    "take_ownership",
)


def compute_granted_mask(effective_dacl, token):
    """执行 AccessCheck，返回 (授予掩码, 拒绝掩码, 是否所有者命中)。"""
    denied = 0
    granted = 0
    owner_hit = bool(
        effective_dacl.owner
        and token.contains_sid(effective_dacl.owner)
    )

    if effective_dacl.null_dacl:
        return rights.KEY_ALL_ACCESS, 0, owner_hit

    for ace in effective_dacl.matching_aces(token):
        # INHERIT_ONLY ACE 只用于向子对象传播，不对当前对象生效
        if ace.flags & rights.INHERIT_ONLY_ACE:
            continue
        mask = ace.access_mask
        if ace.is_deny:
            denied |= mask
            granted &= ~mask
        else:
            granted |= mask & ~denied

    # 所有者隐式权限：即使 DACL 拒绝，也保留读安全与改 DACL 的权利
    if owner_hit:
        granted |= rights.READ_CONTROL | rights.WRITE_DAC

    return granted & 0xFFFFFFFF, denied & 0xFFFFFFFF, owner_hit


def evaluate(keys, target_path, token):
    """计算令牌对目标键的有效访问与审计能力。"""
    from .inheritance import effective_dacl

    effective_dacl = effective_dacl(keys, target_path)
    granted, denied, owner_hit = compute_granted_mask(effective_dacl, token)

    capabilities = {}
    for name, (description, needed) in CAPABILITY_DEFINITIONS.items():
        if name == "read":
            granted_flag = (granted & needed) == needed
        else:
            granted_flag = bool(granted & needed)
        capabilities[name] = Capability(
            name=name,
            description=description,
            granted=granted_flag,
            rights_needed=needed,
        )

    return AccessResult(
        path=effective_dacl.target_path,
        granted_mask=granted,
        denied_mask=denied,
        null_dacl=effective_dacl.null_dacl,
        is_owner=owner_hit,
        effective_dacl=effective_dacl,
        capabilities=capabilities,
    )
def explain_access(access_result, accounts):
    """列出授予/拒绝相关权限的 ACE，供报告溯源。"""
    lines = []
    for ace in access_result.effective_dacl.aces:
        name = accounts.display_name(ace.trustee)
        source = ace.inherited_from or "explicit"
        decision = "DENY" if ace.is_deny else "ALLOW"
        lines.append(
            "%s %s mask=0x%08X via=%s flags=0x%x"
            % (
                decision,
                name,
                ace.access_mask,
                source,
                ace.flags,
            )
        )
    return lines
