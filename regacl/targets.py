"""高价值注册表目标识别。

覆盖四类可导致代码执行的键：

1. 服务键（``ImagePath`` 直接决定服务进程镜像）；
2. 启动项（Run/RunOnce、Winlogon Shell/Userinit 等）；
3. 文件关联（``HKCR\\.ext`` 与 ProgID 绑定）；
4. Shell 命令（ProgID 下的 ``shell\\verb\\command`` 默认值）。
"""

from dataclasses import dataclass, field

from .models import is_under, normalize_path

SERVICES_PREFIX = "HKLM\\SYSTEM\\CurrentControlSet\\Services"

# 服务键中可控制执行的关键值
SERVICE_EXECUTION_VALUES = frozenset(
    {
        "ImagePath",
        "FailureCommand",
        "ServiceDll",
        "ServiceMain",
        "Performance",
    }
)

RUN_KEY_PATHS = frozenset(
    {
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
        "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    }
)

WINLOGON_KEY = (
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
)
WINLOGON_EXECUTION_VALUES = frozenset(
    {"Shell", "Userinit", "AppSetup", "Taskman", "VmApplet"}
)

CLASSES_ROOTS = (
    "HKCR",
    "HKLM\\SOFTWARE\\Classes",
    "HKCU\\SOFTWARE\\Classes",
)


@dataclass
class Target:
    """被识别出的高价值键。"""

    path: str
    category: str
    controlled_values: frozenset = field(default_factory=frozenset)
    detail: str = ""


def _match_classes_root(path):
    for root in CLASSES_ROOTS:
        if is_under(path, root):
            return root
    return None


def classify(path, values=None):
    """识别单个键的目标类别，返回 :class:`Target` 或 ``None``。"""
    path = normalize_path(path)
    values = values or {}

    target = _classify_service(path, values)
    if target:
        return target
    target = _classify_winlogon(path, values)
    if target:
        return target
    if path in RUN_KEY_PATHS:
        return Target(
            path=path,
            category="startup",
            controlled_values=frozenset(values.keys()),
            detail="Run/RunOnce 启动项，每个值在用户登录时执行",
        )
    target = _classify_shell_command(path)
    if target:
        return target
    target = _classify_file_association(path, values)
    if target:
        return target
    return None


def _classify_service(path, values):
    if not is_under(path, SERVICES_PREFIX):
        return None
    relative = path[len(SERVICES_PREFIX):].strip("\\")
    if not relative:
        return Target(
            path=path,
            category="service_root",
            detail="服务根键，可创建任意新服务",
        )
    service_name = relative.split("\\", 1)[0]
    controlled = frozenset(values) & SERVICE_EXECUTION_VALUES

    # 服务参数子键（Parameters\\ServiceDll 等）
    if "\\" in relative:
        sub = relative.split("\\", 1)[1].lower()
        if sub == "parameters":
            controlled = frozenset(values) & frozenset(
                {"ServiceDll", "ServiceMain", "ImagePath"}
            )
        detail = "服务 %s 的参数子键 %s" % (service_name, sub)
    else:
        detail = (
            "服务 %s 的注册键，ImagePath 决定服务进程镜像"
            % service_name
        )
    return Target(
        path=path,
        category="service",
        controlled_values=controlled,
        detail=detail,
    )


def _classify_winlogon(path, values):
    if path != WINLOGON_KEY:
        return None
    controlled = frozenset(values) & WINLOGON_EXECUTION_VALUES
    return Target(
        path=path,
        category="startup",
        controlled_values=controlled,
        detail="Winlogon 自启动键，Shell/Userinit 控制登录执行链",
    )


def _classify_shell_command(path):
    classes_root = _match_classes_root(path)
    if classes_root is None:
        return None
    relative = path[len(classes_root):].strip("\\")
    segments = relative.split("\\")
    # <ProgID>\shell\<verb>\command
    if (
        len(segments) >= 4
        and segments[-2].lower() == "shell"
        and segments[-1].lower() == "command"
    ):
        return Target(
            path=path,
            category="shell_command",
            controlled_values=frozenset({""}),
            detail="Shell 动词命令键，默认值是打开/打印文件时执行的命令行",
        )
    # 形如 <ProgID>\shell\<verb>\command 的四段定位
    if (
        len(segments) >= 3
        and segments[-3].lower() == "shell"
        and segments[-1].lower() == "command"
    ):
        return Target(
            path=path,
            category="shell_command",
            controlled_values=frozenset({""}),
            detail="Shell 动词命令键，默认值是执行的命令行",
        )
    return None


def _classify_file_association(path, values):
    classes_root = _match_classes_root(path)
    if classes_root is None:
        return None
    relative = path[len(classes_root):].strip("\\")
    segments = relative.split("\\")
    # HKCR\.txt 这类扩展名关联键
    if len(segments) == 1 and segments[0].startswith("."):
        return Target(
            path=path,
            category="file_association",
            controlled_values=frozenset(values.keys()) | frozenset({""}),
            detail="扩展名关联键，默认值绑定 ProgID，可劫持打开方式",
        )
    return None


def find_targets(keys):
    """扫描整个键快照，返回全部高价值目标。"""
    results = []
    for path, key in keys.items():
        target = classify(path, key.values)
        if target is not None:
            results.append(target)
    results.sort(key=lambda item: (item.category, item.path))
    return results
