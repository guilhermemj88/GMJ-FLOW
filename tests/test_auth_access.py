import json
import sqlite3
import unittest

from backend.app.services.auth_access import (
    OPERATOR_PERMISSIONS,
    PERMISSION_CATALOG,
    VIEWER_PERMISSIONS,
    active_admin_ids,
    audit_action,
    effective_permissions,
    ensure_auth_schema,
    permission_details,
    revoke_user_sessions,
    session_is_active,
    token_hash,
)


class AuthAccessTest(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        ensure_auth_schema(self.conn)

    def tearDown(self):
        self.conn.close()

    def create_user(self, username, role="viewer", active=True):
        cursor = self.conn.execute(
            """
            INSERT INTO users(
                username, display_name, password_hash, role,
                must_change_password, active, created_at, updated_at
            ) VALUES (?, ?, 'bcrypt-hash-is-not-touched', ?, 0, ?, 'now', 'now')
            """,
            (username, username.title(), role, int(active)),
        )
        return self.conn.execute("SELECT * FROM users WHERE id = ?", (cursor.lastrowid,)).fetchone()

    def test_catalog_is_centralized_and_complete(self):
        expected = {
            "dashboard.view", "dashboard.edit", "dashboard.manage",
            "anomalies.view", "anomalies.manage",
            "mitigations.view", "mitigations.apply", "mitigations.withdraw", "mitigations.configure",
            "bgp.view", "bgp.manage", "bgp.apply",
            "sensors.view", "sensors.manage", "collectors.view", "collectors.manage",
            "cgnat.view", "cgnat.import", "cgnat.manage", "grafana.view", "grafana.manage",
            "users.view", "users.create", "users.edit", "users.disable", "users.delete",
            "users.reset_password", "users.manage_permissions",
            "settings.view", "settings.manage", "audit.view",
        }
        self.assertEqual(expected, set(PERMISSION_CATALOG))
        for code, item in PERMISSION_CATALOG.items():
            self.assertEqual(code, item["code"])
            self.assertTrue(item["name"])
            self.assertTrue(item["description"])
            self.assertTrue(item["category"])
            self.assertIn(item["risk"], {"low", "medium", "high", "critical"})

    def test_schema_migration_is_idempotent_and_preserves_legacy_hash(self):
        legacy = sqlite3.connect(":memory:")
        legacy.row_factory = sqlite3.Row
        legacy.execute(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'viewer',
                must_change_password INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            )
            """
        )
        original_hash = "$2b$12$legacy-hash-must-remain-byte-identical"
        legacy.execute(
            "INSERT INTO users(username, password_hash, role, created_at, updated_at) VALUES ('legacy-user', ?, 'viewer', 'old', 'old')",
            (original_hash,),
        )
        ensure_auth_schema(legacy)
        ensure_auth_schema(legacy)
        row = legacy.execute("SELECT * FROM users WHERE username = 'legacy-user'").fetchone()
        self.assertEqual(original_hash, row["password_hash"])
        self.assertEqual("admin", row["role"])
        self.assertEqual("legacy-user", row["display_name"])
        self.assertEqual(3, legacy.execute("SELECT COUNT(*) FROM roles").fetchone()[0])
        legacy.close()

    def test_role_templates_and_user_overrides(self):
        admin = self.create_user("admin", "admin")
        operator = self.create_user("operator", "operator")
        viewer = self.create_user("viewer", "viewer")
        self.assertEqual(set(PERMISSION_CATALOG), effective_permissions(self.conn, admin))
        self.assertEqual(OPERATOR_PERMISSIONS, effective_permissions(self.conn, operator))
        self.assertEqual(VIEWER_PERMISSIONS, effective_permissions(self.conn, viewer))
        self.assertNotIn("users.edit", effective_permissions(self.conn, viewer))

        self.conn.execute(
            "INSERT INTO user_permission_overrides VALUES (?, 'users.view', 'allow', 'now', 'now')",
            (viewer["id"],),
        )
        self.conn.execute(
            "INSERT INTO user_permission_overrides VALUES (?, 'dashboard.view', 'deny', 'now', 'now')",
            (viewer["id"],),
        )
        permissions = effective_permissions(self.conn, viewer)
        self.assertIn("users.view", permissions)
        self.assertNotIn("dashboard.view", permissions)
        details = {item["code"]: item for item in permission_details(self.conn, viewer)}
        self.assertEqual("allow", details["users.view"]["override"])
        self.assertEqual("deny", details["dashboard.view"]["override"])
        self.assertFalse(details["dashboard.view"]["effective"])

    def test_idempotent_migration_does_not_overwrite_role_customization(self):
        admin_role_id = self.conn.execute("SELECT id FROM roles WHERE key = 'admin'").fetchone()[0]
        self.conn.execute(
            "UPDATE role_permissions SET allowed = 0 WHERE role_id = ? AND permission_key = 'dashboard.edit'",
            (admin_role_id,),
        )
        ensure_auth_schema(self.conn)
        allowed = self.conn.execute(
            "SELECT allowed FROM role_permissions WHERE role_id = ? AND permission_key = 'dashboard.edit'",
            (admin_role_id,),
        ).fetchone()[0]
        self.assertEqual(0, allowed)

    def test_disabled_user_has_no_effective_permissions(self):
        user = self.create_user("disabled-admin", "admin", active=False)
        self.assertEqual(set(), effective_permissions(self.conn, user))

    def test_last_active_admin_is_derived_from_permission_not_role_name(self):
        admin = self.create_user("admin", "admin")
        delegated = self.create_user("delegated", "viewer")
        self.conn.execute(
            "INSERT INTO user_permission_overrides VALUES (?, 'users.manage_permissions', 'allow', 'now', 'now')",
            (delegated["id"],),
        )
        self.assertEqual({admin["id"], delegated["id"]}, set(active_admin_ids(self.conn)))
        self.conn.execute(
            "INSERT INTO user_permission_overrides VALUES (?, 'users.manage_permissions', 'deny', 'now', 'now')",
            (admin["id"],),
        )
        self.assertEqual([delegated["id"]], active_admin_ids(self.conn))

    def test_sessions_store_only_hash_and_can_be_revoked(self):
        user = self.create_user("session-user")
        raw_token = "header.payload.signature"
        digest = token_hash(raw_token)
        self.conn.execute(
            """
            INSERT INTO auth_sessions(id, user_id, token_hash, created_at, expires_at)
            VALUES ('session-1', ?, ?, '2026-01-01T00:00:00+00:00', '2099-01-01T00:00:00+00:00')
            """,
            (user["id"], digest),
        )
        self.assertNotEqual(raw_token, digest)
        self.assertTrue(session_is_active(self.conn, "session-1", user["id"], raw_token, "2026-01-02T00:00:00+00:00"))
        self.assertEqual(1, revoke_user_sessions(self.conn, user["id"], "test"))
        self.assertFalse(session_is_active(self.conn, "session-1", user["id"], raw_token, "2026-01-02T00:00:00+00:00"))

    def test_audit_redacts_sensitive_metadata_and_keeps_correlation(self):
        user = self.create_user("auditor")
        audit_id = audit_action(
            self.conn,
            user_id=user["id"],
            actor_username=user["username"],
            action="user.password.reset",
            resource_type="user",
            resource_id=user["id"],
            correlation_id="request-123",
            metadata={
                "password": "do-not-store",
                "nested": {"access_token": "do-not-store-either"},
                "safe": "kept",
            },
        )
        row = self.conn.execute("SELECT * FROM audit_log WHERE id = ?", (audit_id,)).fetchone()
        metadata = json.loads(row["metadata_json"])
        self.assertEqual("[REDACTED]", metadata["password"])
        self.assertEqual("[REDACTED]", metadata["nested"]["access_token"])
        self.assertEqual("kept", metadata["safe"])
        self.assertEqual("request-123", row["correlation_id"])
        self.assertEqual(user["id"], row["user_id"])


if __name__ == "__main__":
    unittest.main()
