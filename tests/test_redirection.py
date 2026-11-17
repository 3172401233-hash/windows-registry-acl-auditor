import unittest

from regacl import views_for, redirect_32bit
from regacl.redirection import is_reflected


class RedirectionTests(unittest.TestCase):
    def test_software_key_redirects_to_wow6432node(self):
        logical = "HKLM\\SOFTWARE\\Vendor\\App"
        self.assertEqual(
            redirect_32bit(logical),
            "HKLM\\SOFTWARE\\WOW6432Node\\Vendor\\App",
        )

    def test_non_software_key_not_redirected(self):
        path = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\X"
        self.assertEqual(redirect_32bit(path), path)

    def test_reflected_classes_key_not_redirected(self):
        path = "HKLM\\SOFTWARE\\Classes\\.txt"
        self.assertTrue(is_reflected(path))
        self.assertEqual(redirect_32bit(path), path)

    def test_views_for_returns_native_and_wow64_views(self):
        views = views_for("HKLM\\SOFTWARE\\Vendor\\App")
        self.assertEqual(
            [(view, physical) for view, _, physical in views],
            [
                ("native", "HKLM\\SOFTWARE\\Vendor\\App"),
                ("wow64_32", "HKLM\\SOFTWARE\\WOW6432Node\\Vendor\\App"),
            ],
        )

    def test_views_for_reflected_key_single_view(self):
        views = views_for("HKLM\\SOFTWARE\\Classes\\demoFile\\shell\\open\\command")
        self.assertEqual(len(views), 1)
        self.assertEqual(views[0][0], "native")

    def test_views_for_service_key_single_view(self):
        views = views_for(
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Vuln"
        )
        self.assertEqual(len(views), 1)

    def test_physical_wow6432node_key_maps_back_to_logical(self):
        views = views_for(
            "HKLM\\SOFTWARE\\WOW6432Node\\Vendor\\App"
        )
        logicals = {view: logical for view, logical, _ in views}
        self.assertEqual(
            logicals["native"], "HKLM\\SOFTWARE\\Vendor\\App"
        )


if __name__ == "__main__":
    unittest.main()
