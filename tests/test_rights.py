import unittest

from regacl import rights


class GenericMappingTests(unittest.TestCase):
    def test_generic_write_contains_set_value_and_create_subkey(self):
        mapped = rights.map_generic_rights(rights.GENERIC_WRITE)
        self.assertTrue(mapped & rights.KEY_SET_VALUE)
        self.assertTrue(mapped & rights.KEY_CREATE_SUB_KEY)
        self.assertFalse(mapped & rights.KEY_QUERY_VALUE)

    def test_generic_all_expands_to_full_access(self):
        mapped = rights.map_generic_rights(rights.GENERIC_ALL)
        self.assertEqual(mapped, rights.KEY_ALL_ACCESS)
        self.assertTrue(mapped & rights.DELETE)
        self.assertTrue(mapped & rights.WRITE_DAC)
        self.assertTrue(mapped & rights.WRITE_OWNER)

    def test_generic_read_maps_to_key_read(self):
        mapped = rights.map_generic_rights(rights.GENERIC_READ)
        self.assertEqual(mapped, rights.KEY_READ)

    def test_parse_mask_aliases_and_hex(self):
        self.assertEqual(
            rights.parse_mask("KEY_SET_VALUE"),
            rights.KEY_SET_VALUE,
        )
        self.assertEqual(
            rights.parse_mask("KEY_SET_VALUE|DELETE"),
            rights.KEY_SET_VALUE | rights.DELETE,
        )
        self.assertEqual(rights.parse_mask("0x2"), rights.KEY_SET_VALUE)
        self.assertEqual(
            rights.parse_mask(["KEY_SET_VALUE", "WRITE_DAC"]),
            rights.KEY_SET_VALUE | rights.WRITE_DAC,
        )

    def test_parse_mask_generic_alias_is_expanded(self):
        mapped = rights.parse_mask("GENERIC_WRITE")
        self.assertTrue(mapped & rights.KEY_SET_VALUE)
        self.assertFalse(mapped & rights.GENERIC_WRITE)

    def test_mask_to_names_roundtrip(self):
        mask = rights.KEY_SET_VALUE | rights.DELETE | rights.WRITE_DAC
        names = rights.mask_to_names(mask)
        self.assertIn("KEY_SET_VALUE", names)
        self.assertIn("DELETE", names)
        self.assertIn("WRITE_DAC", names)


if __name__ == "__main__":
    unittest.main()
