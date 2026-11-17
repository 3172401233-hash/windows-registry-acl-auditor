"""命令行入口：对离线 JSON 快照执行审计并打印报告。

用法::

    python -m regacl snapshot.json
    python -m regacl snapshot.json --path "HKLM\\SYSTEM\\CurrentControlSet\\Services\\X"

本命令只读取给定文件，不接触真实注册表。
"""

import argparse
import json
import sys

from .analyzer import audit, audit_path
from .loader import load_snapshot


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="离线注册表 ACL 分析器（不操作真实注册表）"
    )
    parser.add_argument("snapshot", help="JSON 注册表快照文件")
    parser.add_argument(
        "--path",
        help="只审计指定键（忽略目标分类），含 WOW64 双视图",
    )
    parser.add_argument(
        "--show-read-only",
        action="store_true",
        help="同时输出只读目标",
    )
    args = parser.parse_args(argv)

    snapshot = load_snapshot(args.snapshot)

    if args.path:
        print(json.dumps(audit_path(snapshot, args.path), indent=2, ensure_ascii=False))
        return 0

    report = audit(snapshot, include_read_only=args.show_read_only)
    print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))

    if report.findings:
        print(
            "\n发现 %d 个普通用户可写的高价值键（其中严重 %d 个）"
            % (
                len(report.findings),
                len(report.critical_keys),
            ),
            file=sys.stderr,
        )
    else:
        print("\n未发现普通用户可写的高价值键。", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
