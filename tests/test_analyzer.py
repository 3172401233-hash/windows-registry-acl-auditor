import json
import unittest
from pathlib import Path

from regacl import audit, audit_path, load_snapshot
from regacl.analyzer import SEVERITY_CRITICAL, SEVERITY_HIGH

from .fixtures import (
    SID_AUTHENTICATED_USERS,
    SID_BUILTIN_USERS,
    SID_LOCAL_SYSTEM,
    SID_TRUSTED_INSTALLER,
    ace,
    build,
    key,
    service_path,
)

SERVICES = "HKLM\\SYSTEM\\CurrentControlSet\\Services"


class AnalyzerTests(unittest.TestCase):
    def test_writable_service_key_is_critical_finding(self):
        snapshot = build({
            SERVICES: key(dacl=[ace(SID_LOCAL_SYSTEM, "KEY_ALL_ACCESS", flags="CI")]),
            service_path("VulnSvc"): key(
                values={"ImagePath": "v.exe"},
                dacl=[ace(SID_BUILTIN_USERS, "KEY_WRITE")],
            ),
        })
        report = audit(snapshot)
        finding = next(
            item for item in report.findings
            if item.path == service_path("VulnSvc")
        )
        self.assertEqual(finding.severity, SEVERITY_CRITICAL)
        self.assertIn("write_value", finding.granted_capabilities)
        self.assertIn("ImagePath", finding.controlled_values)
        self.assertTrue(finding.granting_aces)

    def test_read_only_container_listed_separately(self):
        snapshot = build({
            service_path("LockedSvc"): key(
                values={"ImagePath": "l.exe"},
                dacl=[
                    ace(SID_LOCAL_SYSTEM, "KEY_ALL_ACCESS"),
                    ace(SID_BUILTIN_USERS, "KEY_READ"),
                    ace(
                        SID_BUILTIN_USERS,
                        "KEY_SET_VALUE|DELETE|WRITE_DAC|WRITE_OWNER",
                        deny=True,
                    ),
                ],
                control="P",
            ),
        })
        report = audit(snapshot)
        self.assertFalse(
            any(item.path == service_path("LockedSvc") for item in report.findings)
        )
        read_only = next(
            item for item in report.read_only_targets
            if item["path"] == service_path("LockedSvc")
        )
        self.assertIn("KEY_QUERY_VALUE", read_only["granted_rights"])
        self.assertIn("KEY_SET_VALUE", read_only["denied_rights"])

    def test_protected_account_only_grant_is_not_user_writable(self):
        snapshot = build({
            service_path("TrustedSvc"): key(
                owner=SID_TRUSTED_INSTALLER,
                values={"ImagePath": "t.exe"},
                dacl=[
                    ace(SID_TRUSTED_INSTALLER, "KEY_ALL_ACCESS"),
                    ace(SID_LOCAL_SYSTEM, "KEY_ALL_ACCESS"),
                    ace(SID_BUILTIN_USERS, "KEY_READ"),
                ],
                control="P",
            ),
        })
        report = audit(snapshot)
        self.assertFalse(
            any(
                item.path == service_path("TrustedSvc")
                for item in report.findings
            )
        )
        read_only = next(
            item for item in report.read_only_targets
            if item["path"] == service_path("TrustedSvc")
        )
        self.assertNotIn("KEY_SET_VALUE", read_only["granted_rights"])

    def test_inherited_write_makes_service_writable(self):
        snapshot = build({
            SERVICES: key(dacl=[
                ace(SID_AUTHENTICATED_USERS, "KEY_WRITE", flags="CI|OI"),
            ]),
            service_path("InheritedSvc"): key(
                values={"ImagePath": "i.exe"},
                dacl=[],
            ),
        })
        report = audit(snapshot)
        finding = next(
            item for item in report.findings
            if item.path == service_path("InheritedSvc")
        )
        self.assertIn("write_value", finding.granted_capabilities)
        granting = finding.granting_aces[0]
        self.assertTrue(granting["inherited"])
        self.assertEqual(granting["inherited_from"], SERVICES)

    def test_run_key_and_shell_command_findings(self):
        snapshot = build({
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run": key(
                values={"Updater": "u.exe"},
                dacl=[ace(SID_BUILTIN_USERS, "KEY_SET_VALUE")],
            ),
            r"HKCR\.demo": key(
                values={"": "demoFile"},
                dacl=[ace(SID_BUILTIN_USERS, "KEY_SET_VALUE")],
            ),
            r"HKCR\demoFile\shell\open\command": key(
                values={"": "demo.exe %1"},
                dacl=[ace(SID_BUILTIN_USERS, "KEY_SET_VALUE")],
            ),
        })
        report = audit(snapshot)
        categories = {item.category for item in report.findings}
        self.assertEqual(
            categories, {"startup", "file_association", "shell_command"}
        )
        for finding in report.findings:
            self.assertEqual(finding.severity, SEVERITY_HIGH)

    def test_wow64_redirection_audits_both_views(self):
        logical = r"HKLM\SOFTWARE\Vendor32\Runner"
        physical_32 = r"HKLM\SOFTWARE\WOW6432Node\Vendor32\Runner"
        snapshot = build({
            logical: key(dacl=[ace(SID_BUILTIN_USERS, "KEY_READ")]),
            physical_32: key(
                values={"Command": "r.exe"},
                dacl=[ace(SID_BUILTIN_USERS, "KEY_SET_VALUE|KEY_CREATE_SUB_KEY")],
            ),
        })
        # Runner 不在内置目标分类中，直接用 audit_path 审计双视图
        results = audit_path(snapshot, logical)
        views = {item["view"]: item for item in results}
        self.assertEqual(set(views), {"native", "wow64_32"})
        self.assertFalse(
            views["native"]["capabilities"]["write_value"]
        )
        self.assertTrue(
            views["wow64_32"]["capabilities"]["write_value"]
        )
        self.assertEqual(
            views["wow64_32"]["physical_path"], physical_32
        )

    def test_sample_fixture_end_to_end(self):
        fixture = Path(__file__).resolve().parents[1] / "examples" / "sample_snapshot.json"
        snapshot = load_snapshot(str(fixture))
        report = audit(snapshot)

        critical_paths = {item.path for item in report.critical_keys}
        self.assertIn(service_path("VulnSvc"), critical_paths)
        self.assertIn(service_path("InheritedGroup\\InheritedSvc"), critical_paths)

        # LockedSvc 有拒绝 ACE，不能出现在可写发现里
        writable_paths = {item.path for item in report.findings}
        self.assertNotIn(service_path("LockedSvc"), writable_paths)
        self.assertNotIn(service_path("TrustedSvc"), writable_paths)

        # 序列化可用
        encoded = json.dumps(report.to_dict(), ensure_ascii=False)
        self.assertIn("VulnSvc", encoded)

    def test_hkcu_run_key_audited_as_startup(self):
        snapshot = build({
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run": key(
                values={"Evil": "e.exe"},
                dacl=[ace(SID_BUILTIN_USERS, "KEY_SET_VALUE")],
            ),
        })
        report = audit(snapshot)
        finding = report.findings[0]
        self.assertEqual(finding.category, "startup")
        self.assertIn("Evil", finding.controlled_values)

    def test_services_root_create_subkey_allows_new_service_install(self):
        snapshot = build({
            SERVICES: key(dacl=[
                ace(SID_AUTHENTICATED_USERS, "KEY_CREATE_SUB_KEY|KEY_SET_VALUE"),
            ]),
        })
        report = audit(snapshot)
        finding = next(
            item for item in report.findings if item.path == SERVICES
        )
        self.assertEqual(finding.category, "service_root")
        self.assertIn("create_subkey", finding.granted_capabilities)

    def test_change_permissions_only_still_reported(self):
        snapshot = build({
            service_path("DacWrite"): key(
                values={"ImagePath": "d.exe"},
                dacl=[ace(SID_BUILTIN_USERS, "WRITE_DAC")],
            ),
        })
        report = audit(snapshot)
        finding = report.findings[0]
        self.assertIn("change_permissions", finding.granted_capabilities)
        self.assertNotIn("write_value", finding.granted_capabilities)


if __name__ == "__main__":
    unittest.main()
