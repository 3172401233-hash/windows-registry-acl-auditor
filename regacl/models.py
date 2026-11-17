"""注册表 ACL 分析器的数据模型。

所有数据均来自离线导出的快照，模型本身不执行任何系统调用。
"""

from dataclasses import dataclass, field

from . import rights

# ---- 常见内置 SID（Windows 权威源定义的固定值） ----
SID_NULL = "S-1-0-0"
SID_WORLD = "S-1-1-0"                 # Everyone
SID_LOCAL = "S-1-2-0"                 # Local
SID_NETWORK = "S-1-5-2"               # Network
SID_INTERACTIVE = "S-1-5-4"           # Interactive
SID_SERVICE = "S-1-5-6"               # Service
SID_AUTHENTICATED_USERS = "S-1-5-11"  # Authenticated Users
SID_BUILTIN_USERS = "S-1-5-32-545"    # BUILTIN\\Users
SID_BUILTIN_ADMINISTRATORS = "S-1-5-32-544"
SID_LOCAL_SYSTEM = "S-1-5-18"         # NT AUTHORITY\\SYSTEM
SID_LOCAL_SERVICE = "S-1-5-19"
SID_NETWORK_SERVICE = "S-1-5-20"
SID_TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

WELL_KNOWN_SID_NAMES = {
    SID_NULL: "NULL SID",
    SID_WORLD: "Everyone",
    SID_LOCAL: "LOCAL",
    SID_NETWORK: "NETWORK",
    SID_INTERACTIVE: "INTERACTIVE",
    SID_SERVICE: "SERVICE",
    SID_AUTHENTICATED_USERS: "Authenticated Users",
    SID_BUILTIN_USERS: r"BUILTIN\Users",
    SID_BUILTIN_ADMINISTRATORS: r"BUILTIN\Administrators",
    SID_LOCAL_SYSTEM: r"NT AUTHORITY\SYSTEM",
    SID_LOCAL_SERVICE: r"NT AUTHORITY\LOCAL SERVICE",
    SID_NETWORK_SERVICE: r"NT AUTHORITY\NETWORK SERVICE",
    SID_TRUSTED_INSTALLER: r"NT SERVICE\TrustedInstaller",
}

# 默认视为受保护/高权限的账户：普通用户不会持有这些 SID
DEFAULT_PROTECTED_SIDS = frozenset(
    {
        SID_LOCAL_SYSTEM,
        SID_LOCAL_SERVICE,
        SID_NETWORK_SERVICE,
        SID_BUILTIN_ADMINISTRATORS,
        SID_TRUSTED_INSTALLER,
        "S-1-5-80",  # 所有服务托管账户（NT SERVICE\\*）前缀族
    }
)

# 默认普通用户令牌中的 SID
DEFAULT_USER_SIDS = frozenset(
    {
        "S-1-5-21-1111-2222-3333-1001",  # 模拟的普通域用户
        SID_BUILTIN_USERS,
        SID_AUTHENTICATED_USERS,
        SID_INTERACTIVE,
        SID_WORLD,
        SID_LOCAL,
    }
)


def is_valid_sid(value):
    """轻量 SID 语法校验：S-版本-权威-子权威..."""
    if not isinstance(value, str):
        return False
    parts = value.split("-")
    if len(parts) < 3 or parts[0] != "S":
        return False
    try:
        int(parts[1])
        for part in parts[2:]:
            int(part)
    except ValueError:
        return False
    return True


def sid_matches(token_sid, sid):
    """判断 ACE 受托 SID 是否匹配令牌 SID。

    支持服务托管账户族前缀（如 ``S-1-5-80`` 匹配任意 ``S-1-5-80-...``）。
    """
    if token_sid == sid:
        return True
    if sid == SID_NULL:
        return False
    return token_sid.startswith(sid + "-")


@dataclass(frozen=True)
class ACE:
    """单条 DACL 访问控制项。"""

    trustee: str
    access_mask: int
    ace_type: str = "allow"  # "allow" / "deny"
    flags: int = 0
    inherited: bool = False
    inherited_from: str | None = None

    @property
    def is_deny(self):
        return self.ace_type == "deny"

    @property
    def is_inherit_only(self):
        return bool(self.flags & rights.INHERIT_ONLY_ACE)

    @classmethod
    def from_dict(cls, data):
        ace_type = data.get("type", "allow").lower()
        if ace_type in ("0", "access_allowed", "allowed"):
            ace_type = "allow"
        elif ace_type in ("1", "access_denied", "denied"):
            ace_type = "deny"
        return cls(
            trustee=data["sid"],
            access_mask=rights.parse_mask(data["mask"]),
            ace_type=ace_type,
            flags=_parse_flags(data.get("flags", 0)),
            inherited=bool(data.get("inherited", False)),
            inherited_from=data.get("inherited_from"),
        )


def _parse_flags(value):
    if isinstance(value, int):
        return value
    flag_names = {
        "OI": rights.OBJECT_INHERIT_ACE,
        "CI": rights.CONTAINER_INHERIT_ACE,
        "NP": rights.NO_PROPAGATE_INHERIT_ACE,
        "IO": rights.INHERIT_ONLY_ACE,
        "IA": rights.INHERITED_ACE,
        "OBJECT_INHERIT_ACE": rights.OBJECT_INHERIT_ACE,
        "CONTAINER_INHERIT_ACE": rights.CONTAINER_INHERIT_ACE,
        "NO_PROPAGATE_INHERIT_ACE": rights.NO_PROPAGATE_INHERIT_ACE,
        "INHERIT_ONLY_ACE": rights.INHERIT_ONLY_ACE,
        "INHERITED_ACE": rights.INHERITED_ACE,
    }
    if isinstance(value, str):
        tokens = value.replace("|", ",").replace(" ", ",").split(",")
        mask = 0
        for token in tokens:
            token = token.strip()
            if token and token in flag_names:
                mask |= flag_names[token]
        return mask
    if isinstance(value, (list, tuple, set)):
        mask = 0
        for item in value:
            mask |= _parse_flags(item)
        return mask
    raise TypeError("不支持的 ACE 标志类型: %r" % type(value))


@dataclass
class SecurityDescriptor:
    """键的安全描述符：所有者 + DACL。"""

    owner: str | None = None
    dacl: list[ACE] | None = None  # None 表示 NULL DACL（所有人完全控制）
    dacl_protected: bool = False  # P 标志：阻断继承
    dacl_auto_inherited: bool = True

    @property
    def is_null_dacl(self):
        return self.dacl is None

    @classmethod
    def from_dict(cls, data):
        if data is None:
            return None
        dacl_data = data.get("dacl", [])
        if dacl_data is None:
            dacl = None
        else:
            dacl = [ACE.from_dict(entry) for entry in dacl_data]
        control = data.get("control", "")
        if isinstance(control, str):
            control_flags = {part.strip().upper() for part in control.split("|") if part.strip()}
        else:
            control_flags = set(control or [])
        return cls(
            owner=data.get("owner"),
            dacl=dacl,
            dacl_protected=bool(
                data.get("dacl_protected", False)
            )
            or "P" in control_flags
            or "DACL_PROTECTED" in control_flags,
            dacl_auto_inherited=bool(data.get("dacl_auto_inherited", True)),
        )


@dataclass
class RegistryKey:
    """单个注册表键的离线快照。"""

    path: str
    values: dict[str, str] = field(default_factory=dict)
    security: SecurityDescriptor | None = None
    subkeys: set[str] = field(default_factory=set)
    view: str = "native"  # native / wow64_32 / wow64_64

    def __post_init__(self):
        self.path = normalize_path(self.path)

    @property
    def parent_path(self):
        if "\\" not in self.path:
            return None
        return self.path.rsplit("\\", 1)[0]


HIVE_ALIASES = {
    "HKLM": "HKLM",
    "HKEY_LOCAL_MACHINE": "HKLM",
    "HKCU": "HKCU",
    "HKEY_CURRENT_USER": "HKCU",
    "HKCR": "HKCR",
    "HKEY_CLASSES_ROOT": "HKCR",
    "HKU": "HKU",
    "HKEY_USERS": "HKU",
    "HKCC": "HKCC",
    "HKEY_CURRENT_CONFIG": "HKCC",
}


def normalize_path(path):
    """统一注册表路径格式：大写根键、反斜杠分隔、无首尾斜杠。"""
    if path is None:
        return None
    text = str(path).strip().strip("\\").replace("/", "\\")
    if not text:
        return text
    root, _, rest = text.partition("\\")
    root = HIVE_ALIASES.get(root.upper(), root)
    return root + ("\\" + rest if rest else "")


def is_under(path, prefix):
    path = normalize_path(path)
    prefix = normalize_path(prefix)
    return path == prefix or path.startswith(prefix + "\\")


@dataclass(frozen=True)
class AccountSnapshot:
    """受保护进程账户快照 + 名称解析表。"""

    protected_sids: frozenset = DEFAULT_PROTECTED_SIDS
    name_to_sid: dict[str, str] = field(default_factory=dict)
    sid_to_name: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data):
        protected = set(DEFAULT_PROTECTED_SIDS)
        protected.update(data.get("protected_sids", []))
        name_to_sid = dict(data.get("name_to_sid", {}))
        sid_to_name = dict(data.get("sid_to_name", {}))
        for sid, name in WELL_KNOWN_SID_NAMES.items():
            sid_to_name.setdefault(sid, name)
            name_to_sid.setdefault(name, sid)
        return cls(
            protected_sids=frozenset(protected),
            name_to_sid=name_to_sid,
            sid_to_name=sid_to_name,
        )

    def resolve_sid(self, sid_or_name):
        if is_valid_sid(sid_or_name):
            return sid_or_name
        return self.name_to_sid.get(sid_or_name, sid_or_name)

    def display_name(self, sid):
        return self.sid_to_name.get(sid, sid)

    def is_protected_sid(self, sid):
        for protected in self.protected_sids:
            if sid_matches(sid, protected):
                return True
        return False


@dataclass(frozen=True)
class Token:
    """访问主体（普通用户）的令牌 SID 集合。"""

    sids: frozenset
    is_owner: bool = False

    @classmethod
    def default_user(cls):
        return cls(sids=DEFAULT_USER_SIDS)

    @classmethod
    def from_dict(cls, data):
        return cls(
            sids=frozenset(data.get("sids", DEFAULT_USER_SIDS)),
            is_owner=bool(data.get("is_owner", False)),
        )

    def contains_sid(self, sid):
        for token_sid in self.sids:
            if sid_matches(token_sid, sid):
                return True
        return False
