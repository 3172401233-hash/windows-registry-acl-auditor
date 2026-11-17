"""WOW64 注册表重定向（registry redirection / reflection）建模。

64 位 Windows 上，32 位进程访问部分 ``HKLM\\Software`` 键会被重定向到
``HKLM\\Software\\WOW6432Node``。审计时必须同时检查两个视图，因为攻击者
可能通过 32 位视图写入重定向后的键。
"""

from .models import normalize_path

WOW64_NODE = "HKLM\\SOFTWARE\\WOW6432Node"
WOW64_NODE_UPPER = WOW64_NODE.upper()

# 共享（reflected/shared）键：两个视图看到同一份数据，不重定向
REFLECTED_PREFIXES = (
    "HKLM\\SOFTWARE\\CLASSES",
    "HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\SHELL",
    "HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\DRIVERS",
    "HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\DRIVERDATABASE",
    "HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\CONTROL PANEL",
    "HKLM\\SOFTWARE\\MICROSOFT\\CRYPTOGRAPHY",
    "HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\FONTLINK",
    "HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\FONTS",
    "HKLM\\SOFTWARE\\MICROSOFT\\SYSTEMCERTIFICATES",
)


def is_reflected(path):
    """共享键不参与重定向。"""
    normalized = normalize_path(path).upper()
    return any(
        normalized == prefix or normalized.startswith(prefix + "\\")
        for prefix in REFLECTED_PREFIXES
    )


def redirect_32bit(path):
    """32 位进程访问给定路径时实际落到的键路径。"""
    normalized = normalize_path(path)
    upper = normalized.upper()
    if not upper.startswith("HKLM\\SOFTWARE\\"):
        return normalized
    if upper.startswith(WOW64_NODE_UPPER + "\\") or upper == WOW64_NODE_UPPER:
        return normalized
    if is_reflected(normalized):
        return normalized
    return WOW64_NODE + "\\" + normalized[len("HKLM\\SOFTWARE\\"):]


def views_for(path):
    """返回需要审计的全部视图。

    结果为 ``(视图名, 访问路径, 物理键路径)`` 三元组列表：

    * ``native``：64 位进程看到的原生键；
    * ``wow64_32``：32 位进程被重定向后的物理键。

    共享键与非 Software 键两个视图指向同一物理键，只审计一次。
    """
    normalized = normalize_path(path)
    upper = normalized.upper()
    if not upper.startswith("HKLM\\SOFTWARE\\"):
        return [("native", normalized, normalized)]
    if upper.startswith(WOW64_NODE_UPPER + "\\") or upper == WOW64_NODE_UPPER:
        logical = "HKLM\\SOFTWARE\\" + normalized[len(WOW64_NODE) + 1:]
        return [
            ("native", logical, normalized),
            ("wow64_32", logical, normalized),
        ]
    if is_reflected(normalized):
        return [("native", normalized, normalized)]
    physical_32 = redirect_32bit(normalized)
    return [
        ("native", normalized, normalized),
        ("wow64_32", normalized, physical_32),
    ]


def resolve_view(keys, path, view):
    """在键快照中解析某视图的物理键，缺失时回退逻辑路径。"""
    for view_name, logical, physical in views_for(path):
        if view_name == view:
            if physical in keys:
                return physical
            if logical in keys:
                return logical
            return physical
    return normalize_path(path)
