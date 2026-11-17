"""离线快照加载器。

支持两种输入：

* JSON 快照：包含键树、值、安全描述符（所有者/DACL/控制位）和账户快照；
* Windows ``.reg`` 导出（REGEDIT4 / Windows Registry Editor 5.0 头）：
  只解析键与值，ACL 需通过 JSON 补充（.reg 本身不携带安全信息）。

加载过程完全只读，不调用任何 Win32 API。
"""

import json
from dataclasses import dataclass, field

from .models import (
    AccountSnapshot,
    DEFAULT_PROTECTED_SIDS,
    RegistryKey,
    SecurityDescriptor,
    Token,
    normalize_path,
)


@dataclass
class Snapshot:
    """一次审计的完整输入。"""

    keys: dict[str, RegistryKey] = field(default_factory=dict)
    accounts: AccountSnapshot = field(default_factory=AccountSnapshot)
    token: Token = field(default_factory=Token.default_user)

    def add_key(self, key):
        self.keys[normalize_path(key.path)] = key


def load_snapshot(path):
    """从 JSON 文件加载完整快照。"""
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    return snapshot_from_dict(data)


def snapshot_from_dict(data):
    snapshot = Snapshot()
    if "accounts" in data:
        snapshot.accounts = AccountSnapshot.from_dict(data["accounts"])
    else:
        snapshot.accounts = AccountSnapshot(
            protected_sids=DEFAULT_PROTECTED_SIDS
        )
    if "token" in data:
        snapshot.token = Token.from_dict(data["token"])

    key_dicts = data.get("keys", {})
    if isinstance(key_dicts, dict):
        for path, key_data in key_dicts.items():
            snapshot.add_key(_key_from_dict(path, key_data))
    elif isinstance(key_dicts, list):
        for key_data in key_dicts:
            snapshot.add_key(
                _key_from_dict(key_data["path"], key_data)
            )

    _rebuild_subkeys(snapshot.keys)
    return snapshot


def _key_from_dict(path, data):
    security = SecurityDescriptor.from_dict(data.get("security"))
    return RegistryKey(
        path=path,
        values=dict(data.get("values", {})),
        security=security,
        subkeys=set(data.get("subkeys", [])),
        view=data.get("view", "native"),
    )


def _rebuild_subkeys(keys):
    """根据键路径自动补全父子 subkeys 集合。"""
    for path in keys:
        parent = keys[path].parent_path
        if parent and parent in keys:
            keys[parent].subkeys.add(path)


# ---------------- .reg 导出解析 ----------------

REG_HEADER_5 = "windows registry editor version 5.00"
REG_HEADER_4 = "regedit4"


def load_reg_file(path):
    """解析 .reg 导出，返回只含键/值的 :class:`Snapshot`。"""
    # Regedit 5.0 导出默认为 UTF-16LE（带 BOM），旧版 REGEDIT4 可能为 ANSI
    with open(path, "rb") as handle:
        raw = handle.read()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = raw.decode("utf-16")
    elif raw.startswith(b"\xef\xbb\xbf"):
        text = raw.decode("utf-8-sig")
    else:
        text = raw.decode("utf-8", errors="replace")
    return parse_reg_text(text)


def parse_reg_text(text):
    lines = text.splitlines()
    if not lines:
        raise ValueError(".reg 内容为空")
    header = lines[0].lstrip("\ufeff").strip().lower()
    if header not in (REG_HEADER_5, REG_HEADER_4):
        raise ValueError("无法识别的 .reg 文件头: %r" % lines[0])

    snapshot = Snapshot()
    current_path = None

    for raw_line in lines[1:]:
        line = raw_line.rstrip("\r\n")
        if not line.strip():
            continue
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            current_path = normalize_path(stripped[1:-1])
            if current_path not in snapshot.keys:
                snapshot.add_key(RegistryKey(path=current_path))
            continue
        if current_path is None or "=" not in stripped:
            continue
        name, value = stripped.split("=", 1)
        value_name = _unquote(name.strip())
        if name.strip() == "@":
            value_name = ""
        snapshot.keys[current_path].values[value_name] = _parse_value(value)

    _rebuild_subkeys(snapshot.keys)
    return snapshot


def _unquote(text):
    if len(text) >= 2 and text.startswith('"') and text.endswith('"'):
        inner = text[1:-1]
        result = []
        index = 0
        simple_escapes = {"n": "\n", "r": "\r", "t": "\t", '"': '"'}
        while index < len(inner):
            char = inner[index]
            if char == "\\" and index + 1 < len(inner):
                nxt = inner[index + 1]
                result.append(simple_escapes.get(nxt, nxt))
                index += 2
            else:
                result.append(char)
                index += 1
        return "".join(result)
    return text


def _parse_value(raw):
    raw = raw.strip()
    if raw.startswith('"'):
        return _unquote(raw)
    if ":" in raw:
        type_token, _, data = raw.partition(":")
        return "%s:%s" % (type_token.strip(), data)
    return raw
