"""注册表访问权限位、ACE 标志与泛型映射常量。

数值与 Windows SDK (winnt.h) 中注册表键安全描述符使用的权限位一致，
纯 Python 实现，不依赖 pywin32，也不会触碰真实注册表。
"""

# ---- 标准访问权限 ----
DELETE = 0x00010000
READ_CONTROL = 0x00020000
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
SYNCHRONIZE = 0x00100000

STANDARD_RIGHTS_ALL = 0x001F0000
STANDARD_RIGHTS_READ = READ_CONTROL
STANDARD_RIGHTS_WRITE = READ_CONTROL

# ---- 注册表特定访问权限 ----
KEY_QUERY_VALUE = 0x0001
KEY_SET_VALUE = 0x0002
KEY_CREATE_SUB_KEY = 0x0004
KEY_ENUMERATE_SUB_KEYS = 0x0008
KEY_NOTIFY = 0x0010
KEY_CREATE_LINK = 0x0020

# ---- 泛型访问权限 ----
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
GENERIC_EXECUTE = 0x20000000
GENERIC_ALL = 0x10000000

# 注册表键的泛型映射（GENERIC_MAPPING for registry keys）
GENERIC_MAPPING_TABLE = {
    GENERIC_READ: (
        STANDARD_RIGHTS_READ
        | KEY_QUERY_VALUE
        | KEY_ENUMERATE_SUB_KEYS
        | KEY_NOTIFY
    ),
    GENERIC_WRITE: (
        STANDARD_RIGHTS_WRITE
        | KEY_SET_VALUE
        | KEY_CREATE_SUB_KEY
    ),
    GENERIC_EXECUTE: (
        STANDARD_RIGHTS_READ | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY
    ),
    GENERIC_ALL: STANDARD_RIGHTS_ALL | 0x3F,
}

KEY_READ = (
    STANDARD_RIGHTS_READ
    | KEY_QUERY_VALUE
    | KEY_ENUMERATE_SUB_KEYS
    | KEY_NOTIFY
)
KEY_WRITE = (
    STANDARD_RIGHTS_WRITE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY
)
KEY_EXECUTE = KEY_READ
KEY_ALL_ACCESS = STANDARD_RIGHTS_ALL | 0x3F

# ---- ACE 类型 ----
ACCESS_ALLOWED_ACE_TYPE = 0x0
ACCESS_DENIED_ACE_TYPE = 0x1

# ---- ACE 标志位 ----
OBJECT_INHERIT_ACE = 0x01
CONTAINER_INHERIT_ACE = 0x02
NO_PROPAGATE_INHERIT_ACE = 0x04
INHERIT_ONLY_ACE = 0x08
INHERITED_ACE = 0x10

CONTAINER_INHERIT_FLAGS = (
    OBJECT_INHERIT_ACE
    | CONTAINER_INHERIT_ACE
    | NO_PROPAGATE_INHERIT_ACE
    | INHERIT_ONLY_ACE
)

# 字符串别名 -> 权限位，方便 JSON 快照编写
RIGHT_ALIASES = {
    "DELETE": DELETE,
    "READ_CONTROL": READ_CONTROL,
    "WRITE_DAC": WRITE_DAC,
    "WRITE_OWNER": WRITE_OWNER,
    "SYNCHRONIZE": SYNCHRONIZE,
    "KEY_QUERY_VALUE": KEY_QUERY_VALUE,
    "KEY_SET_VALUE": KEY_SET_VALUE,
    "KEY_CREATE_SUB_KEY": KEY_CREATE_SUB_KEY,
    "KEY_ENUMERATE_SUB_KEYS": KEY_ENUMERATE_SUB_KEYS,
    "KEY_NOTIFY": KEY_NOTIFY,
    "KEY_CREATE_LINK": KEY_CREATE_LINK,
    "GENERIC_READ": GENERIC_READ,
    "GENERIC_WRITE": GENERIC_WRITE,
    "GENERIC_EXECUTE": GENERIC_EXECUTE,
    "GENERIC_ALL": GENERIC_ALL,
    "KEY_READ": KEY_READ,
    "KEY_WRITE": KEY_WRITE,
    "KEY_EXECUTE": KEY_EXECUTE,
    "KEY_ALL_ACCESS": KEY_ALL_ACCESS,
}


def map_generic_rights(mask):
    """把泛型权限位展开成具体权限位，与 RtlMapGenericMask 语义一致。"""
    result = mask
    for generic, concrete in GENERIC_MAPPING_TABLE.items():
        if result & generic:
            result |= concrete
            result &= ~generic
    return result & 0xFFFFFFFF


def parse_mask(value):
    """支持整数、十六进制字符串或权限别名列表解析成权限位掩码。"""
    if isinstance(value, int):
        return map_generic_rights(value)
    if isinstance(value, (list, tuple, set)):
        mask = 0
        for item in value:
            mask |= parse_mask(item)
        return mask
    if isinstance(value, str):
        text = value.strip()
        if text in RIGHT_ALIASES:
            return map_generic_rights(RIGHT_ALIASES[text])
        if "|" in text:
            mask = 0
            for part in text.split("|"):
                mask |= parse_mask(part.strip())
            return mask
        return map_generic_rights(int(text, 0))
    raise TypeError("不支持的权限掩码类型: %r" % type(value))


def mask_to_names(mask):
    """把权限位反向翻译成易读名称（调试/报告用）。"""
    names = []
    for name, bit in RIGHT_ALIASES.items():
        if name.startswith("GENERIC_") or name in (
            "KEY_READ",
            "KEY_WRITE",
            "KEY_EXECUTE",
            "KEY_ALL_ACCESS",
        ):
            continue
        if mask & bit:
            names.append(name)
    return names
