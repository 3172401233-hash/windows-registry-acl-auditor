import unittest

from regacl import rights
from regacl.access import evaluate
from .fixtures import (
    ALICE,
    BOB,
    SID_AUTHENTICATED_USERS,
    SID_BUILTIN_USERS,
    SID_LOCAL_SYSTEM,
    ace,
    build,
    key,
    service_path,
)


class AccessCheckTests(unittest.TestCase):
    def test_explicit_write_grants_set_value_capability(self):
        snapshot = build({
            service_path("Vuln"): key(
                values={"ImagePath": "v.exe"},
                dacl=[
                    ace(SID_LOCAL_SYSTEM, "KEY_ALL_ACCESS"),
                    ace(SID_BUILTIN_USERS, "KEY_WRITE"),
                ],
            ),
        })
        result = evaluate(
            snapshot.keys, service_path("Vuln"), snapshot.token
        )
        self.assertTrue(result.has("write_value"))
        self.assertTrue(result.has("create_subkey"))
        self.assertFalse(result.has("change_permissions"))
        self.assertTrue(result.writable)

    def test_deny_ace_overrides_inherited_allow(self):
        services = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
        snapshot = build({
            services: key(dacl=[
                ace(SID_AUTHENTICATED_USERS, "KEY_ALL_ACCESS", flags="CI|OI"),
            ]),
            service_path("Denied"): key(dacl=[
                ace(SID_BUILTIN_USERS, "KEY_SET_VALUE|DELETE", deny=True),
            ]),
        })
        result = evaluate(
            snapshot.keys, service_path("Denied"), snapshot.token
        )
        self.assertFalse(result.has("write_value"))
        self.assertFalse(result.has("delete_subkey"))
        # 继承的允许仍授予其他位（如创建子键）
        self.assertTrue(result.has("create_subkey"))
        self.assertTrue(result.denied_mask & rights.DELETE)

    def test_null_dacl_grants_everyone_full_control(self):
        snapshot = build({
            service_path("NullDacl"): key(
                values={"ImagePath": "n.exe"},
                dacl=None,
            ),
        })
        result = evaluate(
            snapshot.keys, service_path("NullDacl"), snapshot.token
        )
        self.assertTrue(result.null_dacl)
        self.assertEqual(result.granted_mask, rights.KEY_ALL_ACCESS)
        for capability in ("write_value", "delete_subkey", "change_permissions"):
            self.assertTrue(result.has(capability))

    def test_empty_dacl_grants_nothing(self):
        snapshot = build({
            service_path("Empty"): key(dacl=[]),
        })
        result = evaluate(
            snapshot.keys, service_path("Empty"), snapshot.token
        )
        self.assertEqual(result.granted_mask, 0)
        self.assertFalse(result.writable)
        self.assertFalse(result.has("read"))

    def test_owner_implicitly_holds_write_dac_even_when_denied(self):
        snapshot = build({
            service_path("Owned"): key(
                owner=ALICE,
                dacl=[
                    ace(ALICE, "KEY_READ"),
                    ace(ALICE, "WRITE_DAC", deny=True),
                ],
            ),
        })
        result = evaluate(
            snapshot.keys, service_path("Owned"), snapshot.token
        )
        self.assertTrue(result.is_owner)
        self.assertTrue(result.has("change_permissions"))
        self.assertTrue(result.granted_mask & rights.READ_CONTROL)

    def test_non_owner_unrelated_sid_gets_nothing(self):
        snapshot = build(
            {
                service_path("Stranger"): key(dacl=[
                    ace(BOB, "KEY_ALL_ACCESS"),
                ]),
            },
        )
        result = evaluate(
            snapshot.keys, service_path("Stranger"), snapshot.token
        )
        self.assertEqual(result.granted_mask, 0)
        self.assertFalse(result.writable)

    def test_generic_write_alias_grants_write_capabilities(self):
        snapshot = build({
            service_path("Generic"): key(dacl=[
                ace(SID_BUILTIN_USERS, "GENERIC_WRITE"),
            ]),
        })
        result = evaluate(
            snapshot.keys, service_path("Generic"), snapshot.token
        )
        self.assertTrue(result.has("write_value"))
        self.assertTrue(result.has("create_subkey"))
        self.assertFalse(result.has("delete_subkey"))

    def test_write_owner_alone_flags_take_ownership(self):
        snapshot = build({
            service_path("TakeOwn"): key(dacl=[
                ace(SID_BUILTIN_USERS, "WRITE_OWNER"),
            ]),
        })
        result = evaluate(
            snapshot.keys, service_path("TakeOwn"), snapshot.token
        )
        self.assertTrue(result.has("take_ownership"))
        self.assertFalse(result.has("write_value"))

    def test_custom_token_without_users_group(self):
        snapshot = build(
            {service_path("T1"): key(dacl=[ace(SID_BUILTIN_USERS, "KEY_ALL_ACCESS")])},
            token_sids=[ALICE, SID_AUTHENTICATED_USERS],
        )
        result = evaluate(
            snapshot.keys, service_path("T1"), snapshot.token
        )
        self.assertEqual(result.granted_mask, 0)

    def test_service_sid_family_matching(self):
        service_sid = "S-1-5-80-1234-5678"
        snapshot = build(
            {service_path("SvcAcct"): key(dacl=[ace(service_sid, "KEY_ALL_ACCESS")])},
            token_sids=[service_sid],
        )
        result = evaluate(
            snapshot.keys, service_path("SvcAcct"), snapshot.token
        )
        self.assertTrue(result.has("write_value"))


if __name__ == "__main__":
    unittest.main()
