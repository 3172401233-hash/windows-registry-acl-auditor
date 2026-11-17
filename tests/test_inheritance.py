import unittest

from regacl import rights
from regacl.inheritance import effective_dacl

from .fixtures import (
    ALICE,
    SID_AUTHENTICATED_USERS,
    SID_BUILTIN_USERS,
    SID_LOCAL_SYSTEM,
    ace,
    build,
    key,
    service_path,
)

SERVICES = "HKLM\\SYSTEM\\CurrentControlSet\\Services"


class InheritanceTests(unittest.TestCase):
    def test_container_inherit_ace_reaches_grandchild(self):
        keys = {
            SERVICES: key(dacl=[
                ace(SID_LOCAL_SYSTEM, "KEY_ALL_ACCESS", flags="CI|OI"),
                ace(SID_AUTHENTICATED_USERS, "KEY_WRITE", flags="CI|OI"),
            ]),
            service_path("S1"): key(values={"ImagePath": "x.exe"}, dacl=[]),
        }
        snapshot = build(keys)
        dacl = effective_dacl(snapshot.keys, service_path("S1"))
        inherited = [a for a in dacl.aces if a.inherited]
        self.assertEqual(len(inherited), 2)
        sources = {a.trustee: a.inherited_from for a in inherited}
        self.assertEqual(sources[SID_AUTHENTICATED_USERS], SERVICES)
        for item in inherited:
            self.assertTrue(item.flags & rights.INHERITED_ACE)

    def test_object_inherit_only_does_not_propagate_to_subkey(self):
        keys = {
            SERVICES: key(dacl=[
                ace(SID_BUILTIN_USERS, "KEY_SET_VALUE", flags="OI"),
            ]),
            service_path("S2"): key(dacl=[]),
        }
        snapshot = build(keys)
        dacl = effective_dacl(snapshot.keys, service_path("S2"))
        self.assertEqual(
            [a for a in dacl.aces if a.trustee == SID_BUILTIN_USERS],
            [],
        )

    def test_no_propagate_stops_after_one_level(self):
        group = service_path("Group")
        child = service_path("Group\\Child")
        grandchild = service_path("Group\\Child\\Grand")
        keys = {
            SERVICES: key(dacl=[
                ace(SID_BUILTIN_USERS, "KEY_SET_VALUE", flags="CI|NP"),
            ]),
            group: key(dacl=[]),
            child: key(dacl=[]),
            grandchild: key(dacl=[]),
        }
        snapshot = build(keys)

        child_dacl = effective_dacl(snapshot.keys, child)
        self.assertTrue(
            any(a.trustee == SID_BUILTIN_USERS for a in child_dacl.aces)
        )
        grand_dacl = effective_dacl(snapshot.keys, grandchild)
        self.assertFalse(
            any(a.trustee == SID_BUILTIN_USERS for a in grand_dacl.aces)
        )

    def test_protected_dacl_blocks_all_inheritance(self):
        keys = {
            SERVICES: key(dacl=[
                ace(SID_AUTHENTICATED_USERS, "KEY_ALL_ACCESS", flags="CI|OI"),
            ]),
            service_path("Protected"): key(
                dacl=[ace(SID_BUILTIN_USERS, "KEY_READ")],
                control="P",
            ),
        }
        snapshot = build(keys)
        dacl = effective_dacl(snapshot.keys, service_path("Protected"))
        self.assertTrue(dacl.protected)
        self.assertFalse(any(a.inherited for a in dacl.aces))
        self.assertEqual(len(dacl.aces), 1)

    def test_protected_ancestor_blocks_inheritance_below_it(self):
        group = service_path("BlockedGroup")
        child = service_path("BlockedGroup\\Child")
        keys = {
            SERVICES: key(dacl=[
                ace(SID_AUTHENTICATED_USERS, "KEY_ALL_ACCESS", flags="CI"),
            ]),
            group: key(dacl=[ace(SID_LOCAL_SYSTEM, "KEY_ALL_ACCESS")], control="P"),
            child: key(dacl=[]),
        }
        snapshot = build(keys)
        dacl = effective_dacl(snapshot.keys, child)
        self.assertEqual(dacl.inherited_blocked_by, group)
        self.assertFalse(
            any(a.trustee == SID_AUTHENTICATED_USERS for a in dacl.aces)
        )

    def test_inherit_only_ace_skipped_on_parent_but_applied_to_child(self):
        keys = {
            SERVICES: key(dacl=[
                ace(SID_BUILTIN_USERS, "KEY_SET_VALUE", flags="CI|IO"),
            ]),
            service_path("IOChild"): key(dacl=[]),
        }
        snapshot = build(keys)
        parent_dacl = effective_dacl(snapshot.keys, SERVICES)
        self.assertTrue(parent_dacl.aces[0].is_inherit_only)
        child_dacl = effective_dacl(snapshot.keys, service_path("IOChild"))
        inherited = [
            a for a in child_dacl.aces if a.trustee == SID_BUILTIN_USERS
        ]
        self.assertEqual(len(inherited), 1)
        self.assertFalse(inherited[0].is_inherit_only)

    def test_canonical_ordering_explicit_deny_before_allow_before_inherited(self):
        keys = {
            SERVICES: key(dacl=[
                ace(SID_BUILTIN_USERS, "KEY_SET_VALUE", flags="CI"),
            ]),
            service_path("Order"): key(dacl=[
                ace(SID_BUILTIN_USERS, "KEY_READ"),
                ace(SID_BUILTIN_USERS, "DELETE", deny=True),
            ]),
        }
        snapshot = build(keys)
        dacl = effective_dacl(snapshot.keys, service_path("Order"))
        types = [
            ("deny" if a.is_deny else "allow", a.inherited)
            for a in dacl.aces
        ]
        self.assertEqual(
            types,
            [
                ("deny", False),
                ("allow", False),
                ("allow", True),
            ],
        )

    def test_inherited_ace_declared_in_snapshot_is_not_double_counted(self):
        keys = {
            SERVICES: key(dacl=[
                ace(SID_BUILTIN_USERS, "KEY_SET_VALUE", flags="CI"),
            ]),
            service_path("Dup"): key(dacl=[
                ace(
                    SID_BUILTIN_USERS,
                    "KEY_SET_VALUE",
                    flags="CI|IA",
                    inherited=True,
                    source=SERVICES,
                ),
            ]),
        }
        snapshot = build(keys)
        dacl = effective_dacl(snapshot.keys, service_path("Dup"))
        user_aces = [a for a in dacl.aces if a.trustee == SID_BUILTIN_USERS]
        self.assertEqual(len(user_aces), 1)
        self.assertTrue(user_aces[0].inherited)

    def test_missing_ancestor_does_not_break_chain(self):
        keys = {
            service_path("Orphan"): key(dacl=[
                ace(ALICE, "KEY_SET_VALUE"),
            ]),
        }
        snapshot = build(keys)
        dacl = effective_dacl(snapshot.keys, service_path("Orphan"))
        self.assertEqual(len(dacl.aces), 1)


if __name__ == "__main__":
    unittest.main()
