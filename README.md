# windows-registry-acl-auditor

Python Windows 注册表 ACL 分析器：基于**离线导出的注册表快照**计算普通用户对
目标键的有效权限，定位能被用来劫持服务执行、启动项、文件关联和 Shell 命令的
可写键，并指出具体权限与命中的 ACE 来源。

> **本工具不直接操作注册表。** 它只读取 JSON 快照或 `.reg` 导出文件，在纯
> Python 数据结构上完成 ACL 计算，不调用 `winreg`、`advapi32` 或任何 Win32
> API，不打开、不写入、不删除任何真实注册表键，可在 Linux/macOS 上运行。

## 解决的问题

服务参数（如 `HKLM\SYSTEM\CurrentControlSet\Services\<名>\ImagePath`）若位于
普通用户可写的注册表键下，攻击者改写 `ImagePath` 后即可让系统下次启动以
`SYSTEM` 身份执行任意程序。只检查键值内容无法发现该风险，必须计算键的
**有效 ACL**：显式 ACE、继承 ACE、拒绝项、所有者权利和 WOW64 重定向视图。

## 能力概览

- 解析 JSON 快照（键树、值、所有者、DACL、控制位）与 Windows `.reg` 导出；
- 模拟 Windows 自动继承：`OI/CI/NP/IO/IA` 标志、`DACL_PROTECTED` 保护边界；
- 按规范顺序执行 AccessCheck：拒绝优先、NULL/空 DACL、所有者隐式 `WRITE_DAC`；
- 泛型权限展开（`GENERIC_WRITE`、`KEY_WRITE`、`KEY_ALL_ACCESS` 等）；
- 受保护进程账户快照：区分普通用户 SID 与 `SYSTEM`/`TrustedInstaller`/服务账户；
- WOW64 注册表重定向：同时审计 64 位原生视图与 32 位 `WOW6432Node` 视图；
- 识别服务键、Run/RunOnce、Winlogon、文件关联与 `shell\verb\command` 目标；
- 输出可控制执行的关键键、具体能力（写值/建子键/删除/改权限/夺权）及溯源 ACE。

## 安装与测试

无需第三方依赖，Python 3.10+ 即可：

```bash
python -m unittest
```

## 快速开始

```bash
# 对快照做完整审计，打印 JSON 报告
python -m regacl examples/sample_snapshot.json

# 顺带列出只读目标
python -m regacl examples/sample_snapshot.json --show-read-only

# 跳过目标分类，直接审计任意键（自动包含 WOW64 双视图）
python -m regacl examples/sample_snapshot.json \
  --path "HKLM\SOFTWARE\Vendor32\Runner"
```

库调用：

```python
from regacl import load_snapshot, audit, audit_path, evaluate

snapshot = load_snapshot("examples/sample_snapshot.json")
report = audit(snapshot)

for finding in report.critical_keys:
    print(finding.path, finding.granted_capabilities, finding.controlled_values)

# 单键有效访问
result = evaluate(
    snapshot.keys,
    r"HKLM\SYSTEM\CurrentControlSet\Services\VulnSvc",
    snapshot.token,
)
print(result.has("write_value"), result.granted_mask)
```

## 审计能力定义

| 能力 | 所需权限位 | 攻击含义 |
| --- | --- | --- |
| `write_value` | `KEY_SET_VALUE` | 改写 `ImagePath`、Run 值或命令行 |
| `create_subkey` | `KEY_CREATE_SUB_KEY` | 新建服务、Run 项或 ProgID 注册 |
| `delete_subkey` | `DELETE` | 删除/替换现有服务注册 |
| `change_permissions` | `WRITE_DAC` | 给自己追加写权限 |
| `take_ownership` | `WRITE_OWNER` | 夺取所有权后重写 DACL |
| `read` | `KEY_QUERY_VALUE \| KEY_ENUMERATE_SUB_KEYS` | 仅读取，不构成写入 |

键所有者无论 DACL 如何设置，都隐式持有 `READ_CONTROL | WRITE_DAC`。

## 快照格式

```json
{
  "accounts": {
    "protected_sids": ["S-1-5-18", "S-1-5-80"],
    "sid_to_name": {"S-1-5-32-545": "BUILTIN\\Users"}
  },
  "token": {
    "sids": ["S-1-5-21-...-1001", "S-1-5-32-545", "S-1-5-11"]
  },
  "keys": {
    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\VulnSvc": {
      "values": {"ImagePath": "C:\\Windows\\vulnsvc.exe"},
      "security": {
        "owner": "S-1-5-18",
        "control": "P",
        "dacl": [
          {"sid": "S-1-5-32-545", "mask": "KEY_WRITE", "flags": "CI|OI"},
          {"sid": "S-1-5-32-545", "type": "deny", "mask": "DELETE"}
        ]
      }
    }
  }
}
```

- `mask` 支持整数、十六进制字符串、权限别名或 `A|B` 组合；
- `flags` 支持 `OI/CI/NP/IO/IA` 别名；`"dacl": null` 表示 NULL DACL；
- `.reg` 导出只含键和值，安全描述符需通过 JSON 快照补充。

## 模块结构

- `regacl/rights.py`：权限位、ACE 标志与泛型映射；
- `regacl/models.py`：SID、ACE、安全描述符、注册表键、令牌、账户快照；
- `regacl/inheritance.py`：继承引擎与有效 DACL 计算；
- `regacl/access.py`：AccessCheck 与审计能力判定；
- `regacl/redirection.py`：WOW64 注册表重定向视图；
- `regacl/targets.py`：服务/启动/文件关联/Shell 命令目标分类；
- `regacl/loader.py`：JSON 与 `.reg` 离线加载；
- `regacl/analyzer.py`：审计主流程与报告模型。

## 安全边界

本项目仅用于防御性配置审计与安全测试，分析结论依赖输入快照的完整性；
它不修改系统状态，也不替代在真实主机上的加固验证。
