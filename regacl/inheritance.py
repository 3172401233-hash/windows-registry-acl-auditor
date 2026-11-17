"""注册表键 DACL 继承引擎。

实现 Windows 自动继承（auto-inheritance）的核心语义：

* 带 ``DACL_PROTECTED`` (P) 标志的键只保留自身显式 ACE；
* 否则沿父键链收集可继承 ACE，按 OI/CI/NP/IO 标志传播；
* 输出按 Windows 规范顺序排列的有效 DACL（显式拒绝 -> 显式允许
  -> 继承项，继承项按来源深度排序，同层拒绝在前）。
"""

from . import rights
from .models import ACE, SecurityDescriptor, normalize_path


def _explicit_aces(security):
    """返回键自身的显式 ACE（剔除快照里标记为继承的条目）。"""
    if security is None or security.dacl is None:
        return []
    return [ace for ace in security.dacl if not ace.inherited]


def _propagate_flags(flags):
    """父 ACE 继承到子键容器后，在子键上的有效继承标志。"""
    propagated = flags & ~(
        rights.INHERIT_ONLY_ACE | rights.INHERITED_ACE
    )
    if propagated & rights.NO_PROPAGATE_INHERIT_ACE:
        # NP：只继承一级，到达子对象后清除 OI/CI/NP
        propagated &= ~(
            rights.OBJECT_INHERIT_ACE
            | rights.CONTAINER_INHERIT_ACE
            | rights.NO_PROPAGATE_INHERIT_ACE
        )
    return propagated


def _ancestor_chain(keys, target_path):
    """从根到目标父键的安全描述符链（缺失祖先跳过）。"""
    chain = []
    parts = target_path.split("\\")
    for depth in range(1, len(parts)):
        ancestor_path = normalize_path("\\".join(parts[:depth]))
        key = keys.get(ancestor_path)
        if key is not None and key.security is not None:
            chain.append((ancestor_path, key.security))
    return chain


def collect_inherited_aces(keys, target_path):
    """沿父链收集适用于目标键的继承 ACE。

    返回 ``(inherited_aces, blocked_by)``；当某个祖先启用 DACL 保护时，
    该祖先之上的继承全部被阻断，``blocked_by`` 记录保护键路径。
    """
    inherited = []
    blocked_by = None

    chain = _ancestor_chain(keys, target_path)

    # 每条显式可继承 ACE 独立沿祖先链向下传播
    for source_depth, (source_path, source_security) in enumerate(chain):
        if source_security.dacl is None:
            continue
        for ace in source_security.dacl:
            if ace.inherited:
                continue
            if not (ace.flags & rights.CONTAINER_INHERIT_ACE):
                # 注册表子键都是容器：只有带 CI 的 ACE 可继承
                continue

            original_flags = ace.flags
            no_propagate = bool(
                original_flags & rights.NO_PROPAGATE_INHERIT_ACE
            )
            reachable = True
            # 沿 source 之下的祖先链逐跳传播（含保护边界检查）
            hops = chain[source_depth + 1:]
            for hop_index, (hop_path, hop_security) in enumerate(
                hops, start=1
            ):
                if hop_security.dacl_protected:
                    reachable = False
                    blocked_by = hop_path
                    break
                if no_propagate and hop_index >= 2:
                    # NP：只向直接子容器继承一级
                    reachable = False
                    break

            if not reachable:
                continue

            # 计算到达目标时的有效标志：NP 后无 OI/CI，普通继承保留
            final_flags = _propagate_flags(original_flags)
            if not no_propagate:
                final_flags |= original_flags & (
                    rights.OBJECT_INHERIT_ACE
                    | rights.CONTAINER_INHERIT_ACE
                )
            final_flags |= rights.INHERITED_ACE

            inherited.append(
                ACE(
                    trustee=ace.trustee,
                    access_mask=ace.access_mask,
                    ace_type=ace.ace_type,
                    flags=final_flags,
                    inherited=True,
                    inherited_from=source_path,
                )
            )
    return inherited, blocked_by


def _canonical_order(entry):
    """Windows DACL 规范顺序排序键。

    层级：显式拒绝(0) -> 显式允许(1) -> 继承项(2+)；
    继承项内部按继承来源深度（越近越靠前），同深度拒绝优先。
    """
    ace, depth = entry
    if not ace.inherited:
        return (0 if ace.is_deny else 1, 0, 0 if ace.is_deny else 1)
    return (2, depth, 0 if ace.is_deny else 1)


def effective_dacl(keys, target_path):
    """计算目标键的有效 DACL。

    返回 :class:`EffectiveDacl`。NULL DACL 单独标识，表示任何人完全控制。
    """
    target_path = normalize_path(target_path)
    key = keys.get(target_path)
    own_security = key.security if key is not None else None

    explicit = _explicit_aces(own_security)

    if own_security is not None and own_security.dacl is None:
        return EffectiveDacl(
            target_path=target_path,
            aces=[],
            null_dacl=True,
            protected=own_security.dacl_protected,
            owner=own_security.owner,
            inherited_blocked_by=None,
        )

    inherited = []
    blocked_by = None
    if own_security is None or not own_security.dacl_protected:
        inherited, blocked_by = collect_inherited_aces(keys, target_path)

    # 记录每个继承 ACE 的来源深度用于规范排序
    depth_map = {}
    if inherited:
        for index, ace in enumerate(inherited):
            depth_map[index] = ace.inherited_from.count("\\")

    ordered_entries = [(ace, 0) for ace in explicit]
    ordered_entries.extend(
        (ace, depth_map.get(index, 0))
        for index, ace in enumerate(inherited)
    )
    ordered_entries.sort(key=_canonical_order)

    return EffectiveDacl(
        target_path=target_path,
        aces=[entry[0] for entry in ordered_entries],
        null_dacl=False,
        protected=bool(
            own_security is not None and own_security.dacl_protected
        ),
        owner=own_security.owner if own_security is not None else None,
        inherited_blocked_by=blocked_by,
    )


class EffectiveDacl:
    """有效 DACL 计算结果。"""

    def __init__(
        self,
        target_path,
        aces,
        null_dacl,
        protected,
        owner,
        inherited_blocked_by,
    ):
        self.target_path = target_path
        self.aces = aces
        self.null_dacl = null_dacl
        self.protected = protected
        self.owner = owner
        self.inherited_blocked_by = inherited_blocked_by

    def matching_aces(self, token):
        """筛选出与令牌 SID 相关的 ACE，保持规范顺序。"""
        return [ace for ace in self.aces if token.contains_sid(ace.trustee)]

    def __repr__(self):
        return (
            "EffectiveDacl(path=%r, aces=%d, null=%s, protected=%s)"
            % (self.target_path, len(self.aces), self.null_dacl, self.protected)
        )
