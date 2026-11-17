import tempfile
import unittest
from pathlib import Path

from regacl.loader import load_reg_file


REG_EXPORT = (
    "Windows Registry Editor Version 5.00\r\n"
    "\r\n"
    r"[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RegSvc]"
    + "\r\n"
    '"ImagePath"="C:\\\\Windows\\\\regsvc.exe"' + "\r\n"
)


class RegFileIOTests(unittest.TestCase):
    def test_load_utf16_reg_file_from_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "export.reg"
            path.write_text(REG_EXPORT, encoding="utf-16")
            snapshot = load_reg_file(str(path))
        key = snapshot.keys[
            r"HKLM\SYSTEM\CurrentControlSet\Services\RegSvc"
        ]
        self.assertEqual(key.values["ImagePath"], r"C:\Windows\regsvc.exe")

    def test_load_utf8_reg_file_from_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "export.reg"
            path.write_text(REG_EXPORT, encoding="utf-8")
            snapshot = load_reg_file(str(path))
        self.assertEqual(len(snapshot.keys), 1)


if __name__ == "__main__":
    unittest.main()
