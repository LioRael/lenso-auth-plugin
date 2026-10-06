#!/usr/bin/env python3
"""Exercise owner SQL predicates using only a private in-memory SQLite fixture.

This verifies migration compatibility and conditional durable intent/activation,
not Rust, PostgreSQL, D1 transport or full App behavior. No credentials or network.
"""
import json
import re
import sqlite3
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OWNER = ROOT / "crates/lenso-auth-account-plugin"
SOURCE = (OWNER / "src/storage/operator_binding.rs").read_text()
INTENT = re.search(r'const ACTIVATION_INTENT_D1: &str = "([^"]+)";', SOURCE)[1]
ACTIVATE = re.search(r'statement\("(UPDATE auth_operator_bindings SET status=\'active\'[^"\n]+)"', SOURCE)[1]


class IntentFixture(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        # Apply the real old owner history, seed an existing pending record,
        # then upgrade without replacing that record or identity.
        for migration in sorted((OWNER / "migrations/d1").glob("00[1-4]_*.sql")):
            self.db.executescript(migration.read_text())
        self.db.execute("INSERT INTO identity_subjects(subject_id,status) VALUES('usr_operator','active')")
        self.db.execute("INSERT INTO auth_operator_bindings(binding_id,source_issuer,source_subject,deployment,operator_subject,scope_kind,scope_id,revision,status) VALUES('opb_fixture','fixture.accounts','usr_source','synthetic','usr_operator','deployment','synthetic',1,'pending')")
        self.db.executescript((OWNER / "migrations/d1/005_operator_activation_intents.sql").read_text())

    def tearDown(self):
        self.db.close()

    def row(self):
        return self.db.execute("SELECT * FROM auth_operator_bindings").fetchone()

    def intent(self, *, revision=1, scope="synthetic", timestamp="2026-10-06T10:00:00.000000000Z", permissions='["fixture.read"]'):
        return self.db.execute(INTENT, (timestamp, permissions, "opb_fixture", revision,
            "fixture.accounts", "synthetic", "deployment", scope)).rowcount

    def test_upgrade_preserves_original_pending_identity_and_revision(self):
        row = self.row()
        self.assertEqual((row["binding_id"], row["operator_subject"], row["revision"], row["status"]),
            ("opb_fixture", "usr_operator", 1, "pending"))
        self.assertEqual((row["activation_started_at"], row["activation_permissions"]), ("", ""))
        self.assertEqual(self.db.execute("SELECT count(*) FROM auth_sessions").fetchone()[0], 0)

    def test_concurrent_or_response_loss_retry_keeps_first_complete_intent(self):
        self.assertEqual(self.intent(), 1)
        first = dict(self.row())
        self.assertEqual(self.intent(timestamp="2026-10-06T10:01:00.000000000Z", permissions='["fixture.write"]'), 0)
        self.assertEqual(dict(self.row()), first)
        self.assertEqual(json.loads(first["activation_permissions"]), ["fixture.read"])

    def test_wrong_revision_and_scope_cannot_claim_intent(self):
        self.assertEqual(self.intent(revision=2), 0)
        self.assertEqual(self.intent(scope="another"), 0)
        self.assertEqual(self.row()["activation_started_at"], "")

    def test_active_and_revoked_cannot_change_intent_or_activation_receipt(self):
        self.intent()
        params = ("audit_fixed", "policy_1", "opb_fixture", 1,
            "fixture.accounts", "synthetic", "deployment", "synthetic")
        self.assertEqual(self.db.execute(ACTIVATE, params).rowcount, 1)
        self.assertEqual(self.db.execute(ACTIVATE, ("audit_other", "policy_2", *params[2:])).rowcount, 0)
        self.assertEqual((self.row()["audit_event_id"], self.row()["policy_revision"]), ("audit_fixed", "policy_1"))
        self.assertEqual(self.intent(timestamp="2026-10-06T10:02:00Z"), 0)
        self.db.execute("UPDATE auth_operator_bindings SET status='revoked',revision=2")
        self.assertEqual(self.intent(), 0)
        self.assertEqual(self.db.execute(ACTIVATE, params).rowcount, 0)
        self.assertEqual((self.row()["status"], self.row()["revision"]), ("revoked", 2))

    def test_partial_corrupt_intent_is_not_overwritten(self):
        self.db.execute("UPDATE auth_operator_bindings SET activation_started_at='2026-10-06T10:00:00Z'")
        self.assertEqual(self.intent(), 0)
        self.assertEqual(self.row()["activation_permissions"], "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
