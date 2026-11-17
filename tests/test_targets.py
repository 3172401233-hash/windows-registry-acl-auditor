import unittest

from regacl.targets import classify, find_targets
from regacl.loader import snapshot_from_dict


class TargetClassificationTests(unittest.TestCase):
    def test_service_key_with_image_path(self):
        target = classify(
            r"HKLM\SYSTEM\CurrentControlSet\Services\VulnSvc",
            {"ImagePath": "v.exe", "Start": 2},
        )
        self.assertEqual(target.category, "service")
        self.assertIn("ImagePath", target.controlled_values)

    def test_service_parameters_dll(self):
        target = classify(
            r"HKLM\SYSTEM\CurrentControlSet\Services\Svc\Parameters",
            {"ServiceDll": "x.dll"},
        )
        self.assertEqual(target.category, "service")
        self.assertIn("ServiceDll", target.controlled_values)

    def test_services_root_identified(self):
        target = classify(r"HKLM\SYSTEM\CurrentControlSet\Services")
        self.assertEqual(target.category, "service_root")

    def test_run_key_startup(self):
        target = classify(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            {"Updater": "u.exe"},
        )
        self.assertEqual(target.category, "startup")
        self.assertIn("Updater", target.controlled_values)

    def test_winlogon_shell_values(self):
        target = classify(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            {"Shell": "explorer.exe", "Userinit": "userinit.exe,"},
        )
        self.assertEqual(target.category, "startup")
        self.assertIn("Shell", target.controlled_values)
        self.assertIn("Userinit", target.controlled_values)

    def test_file_extension_association(self):
        target = classify(r"HKCR\.txt", {"": "txtfile"})
        self.assertEqual(target.category, "file_association")

    def test_shell_command_key(self):
        target = classify(
            r"HKCR\txtfile\shell\open\command",
            {"": "notepad.exe %1"},
        )
        self.assertEqual(target.category, "shell_command")
        self.assertIn("", target.controlled_values)

    def test_unrelated_key_returns_none(self):
        self.assertIsNone(
            classify(r"HKLM\SOFTWARE\Vendor\Settings", {"Flag": "1"})
        )

    def test_find_targets_scans_snapshot(self):
        snapshot = snapshot_from_dict({
            "keys": {
                r"HKLM\SYSTEM\CurrentControlSet\Services\A": {
                    "values": {"ImagePath": "a.exe"},
                    "security": {"owner": "S-1-5-18", "dacl": []},
                },
                r"HKLM\SOFTWARE\Random": {
                    "values": {"X": "1"},
                    "security": {"owner": "S-1-5-18", "dacl": []},
                },
            }
        })
        targets = find_targets(snapshot.keys)
        paths = {item.path for item in targets}
        self.assertIn(r"HKLM\SYSTEM\CurrentControlSet\Services\A", paths)
        self.assertNotIn(r"HKLM\SOFTWARE\Random", paths)


if __name__ == "__main__":
    unittest.main()
