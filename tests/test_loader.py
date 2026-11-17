import json
import tempfile
import unittest
from pathlib import Path

from regacl.loader import load_snapshot, parse_reg_text, snapshot_from_dict
from regacl.models import (
    SID_BUILTIN_USERS,
    SID_LOCAL_SYSTEM,
    SecurityDescriptor,
)


class JsonLoaderTests(unittest.TestCase):
    def test_loads_keys_values_and_security(self):
        snapshot = snapshot_from_dict({
            "keys": {
                r"HKLM\SYSTEM\CurrentControlSet\Services\S": {
                    "values": {"ImagePath": "s.exe"},
                    "security": {
                        "owner": SID_LOCAL_SYSTEM,
                        "control": "P",
                        "dacl": [
                            {"sid": SID_BUILTIN_USERS, "mask": "KEY_READ"}
                        ],
                    },
                }
            }
        })
        key = snapshot.keys[r"HKLM\SYSTEM\CurrentControlSet\Services\S"]
        self.assertEqual(key.values["ImagePath"], "s.exe")
        self.assertIsInstance(key.security, SecurityDescriptor)
        self.assertTrue(key.security.dacl_protected)
        self.assertEqual(key.security.dacl[0].trustee, SID_BUILTIN_USERS)

    def test_null_dacl_preserved(self):
        snapshot = snapshot_from_dict({
            "keys": {
                r"HKLM\SOFTWARE\X": {
                    "security": {"owner": SID_LOCAL_SYSTEM, "dacl": None}
                }
            }
        })
        self.assertIsNone(
            snapshot.keys[r"HKLM\SOFTWARE\X"].security.dacl
        )

    def test_subkeys_rebuilt_from_path_tree(self):
        snapshot = snapshot_from_dict({
            "keys": {
                r"HKLM\SOFTWARE\Parent": {"security": {"dacl": []}},
                r"HKLM\SOFTWARE\Parent\Child": {"security": {"dacl": []}},
            }
        })
        self.assertIn(
            r"HKLM\SOFTWARE\Parent\Child",
            snapshot.keys[r"HKLM\SOFTWARE\Parent"].subkeys,
        )

    def test_load_snapshot_from_file(self):
        data = {
            "token": {"sids": ["S-1-5-32-545"]},
            "keys": {
                r"HKLM\SOFTWARE\X": {
                    "security": {
                        "owner": SID_LOCAL_SYSTEM,
                        "dacl": [
                            {"sid": SID_BUILTIN_USERS, "mask": "KEY_SET_VALUE"}
                        ],
                    }
                }
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            file_path = Path(tmp) / "snap.json"
            file_path.write_text(json.dumps(data), encoding="utf-8")
            snapshot = load_snapshot(str(file_path))
        self.assertEqual(
            set(snapshot.token.sids), {SID_BUILTIN_USERS}
        )


REG_EXPORT = (
    "Windows Registry Editor Version 5.00\r\n"
    "\r\n"
    r"[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RegSvc]" + "\r\n"
    '"ImagePath"="C:\\\\Windows\\\\regsvc.exe"' + "\r\n"
    '"Start"=dword:00000002' + "\r\n"
    "\r\n"
    r"[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run]"
    + "\r\n"
    '@="C:\\\\Tools\\\\x.exe"' + "\r\n"
)


class RegFileTests(unittest.TestCase):
    def test_parse_reg_export_keys_and_values(self):
        snapshot = parse_reg_text(REG_EXPORT)
        service = snapshot.keys[
            r"HKLM\SYSTEM\CurrentControlSet\Services\RegSvc"
        ]
        self.assertEqual(
            service.values["ImagePath"], r"C:\Windows\regsvc.exe"
        )
        self.assertTrue(service.values["Start"].startswith("dword:"))

    def test_parse_reg_default_value_at_sign(self):
        snapshot = parse_reg_text(REG_EXPORT)
        run_key = snapshot.keys[
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        ]
        self.assertEqual(run_key.values[""], r"C:\Tools\x.exe")

    def test_reg_export_has_no_security_descriptors(self):
        snapshot = parse_reg_text(REG_EXPORT)
        for key in snapshot.keys.values():
            self.assertIsNone(key.security)

    def test_bad_header_raises(self):
        with self.assertRaises(ValueError):
            parse_reg_text("not a reg file\n")


if __name__ == "__main__":
    unittest.main()
