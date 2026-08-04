import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

try:
    from starlette.requests import Request
    from app import main
except (ImportError, SyntaxError):  # Local lightweight environments may omit backend dependencies.
    Request = None
    main = None


@unittest.skipIf(main is None, "backend runtime dependencies are not installed")
class AuthApiTest(unittest.TestCase):
    def setUp(self):
        handle = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        handle.close()
        self.db_path = Path(handle.name)
        self.path_patch = patch.object(main, "sqlite_path", return_value=self.db_path)
        self.ensure_patch = patch.object(main, "ensure_sensor_db", return_value=None)
        self.path_patch.start()
        self.ensure_patch.start()
        self.addCleanup(self.path_patch.stop)
        self.addCleanup(self.ensure_patch.stop)
        with main.sqlite_connection() as conn:
            main.ensure_auth_schema(conn)
            conn.commit()
        main.AUTH_LOGIN_RATE_STATE.clear()

    def tearDown(self):
        try:
            os.unlink(str(self.db_path))
        except OSError:
            pass

    def request(self, method="GET", path="/", token=""):
        headers = [(b"user-agent", b"gmj-flow-auth-test")]
        if token:
            headers.append((b"authorization", f"Bearer {token}".encode("ascii")))
        return Request(
            {
                "type": "http",
                "http_version": "1.1",
                "scheme": "http",
                "method": method,
                "path": path,
                "raw_path": path.encode("ascii"),
                "query_string": b"",
                "headers": headers,
                "client": ("127.0.0.1", 12345),
                "server": ("testserver", 80),
            }
        )

    def create_user(self, username="admin", password="correct horse battery staple", role="admin", active=True, must_change=False):
        now = main.utc_now_iso()
        with main.sqlite_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO users(
                    username, display_name, password_hash, role,
                    must_change_password, active, password_changed_at,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    username, username.title(), main.hash_password(password), role,
                    int(must_change), int(active), now, now, now,
                ),
            )
            row = main.fetch_user_by_id(conn, cursor.lastrowid)
            public = main.user_row_to_public(row, conn, include_permission_details=True)
            conn.commit()
        return public

    def actor_request(self, actor, method="POST", path="/api/v1/users"):
        request = self.request(method, path)
        request.state.user = actor
        request.state.auth_session_id = ""
        return request

    def assert_http_status(self, expected, callback):
        with self.assertRaises(main.HTTPException) as caught:
            callback()
        self.assertEqual(expected, caught.exception.status_code)
        return caught.exception

    def test_login_correct_wrong_unknown_and_disabled(self):
        self.create_user()
        success = main.auth_login(
            main.LoginPayload(username="admin", password="correct horse battery staple"),
            self.request("POST", "/api/v1/auth/login"),
        )
        self.assertTrue(success["ok"])
        self.assertTrue(success["token"])
        self.assertNotIn("password_hash", success["user"])
        self.assertTrue(success["user"]["last_login_at"])

        wrong = self.assert_http_status(
            401,
            lambda: main.auth_login(
                main.LoginPayload(username="admin", password="incorrect password"),
                self.request("POST", "/api/v1/auth/login"),
            ),
        )
        unknown = self.assert_http_status(
            401,
            lambda: main.auth_login(
                main.LoginPayload(username="does-not-exist", password="incorrect password"),
                self.request("POST", "/api/v1/auth/login"),
            ),
        )
        self.assertEqual(wrong.detail, unknown.detail)

        self.create_user("disabled", role="viewer", active=False)
        disabled = self.assert_http_status(
            401,
            lambda: main.auth_login(
                main.LoginPayload(username="disabled", password="correct horse battery staple"),
                self.request("POST", "/api/v1/auth/login"),
            ),
        )
        self.assertEqual(wrong.detail, disabled.detail)

    def test_lockout_after_repeated_failures(self):
        self.create_user()
        with patch.object(main, "AUTH_MAX_FAILED_ATTEMPTS", 3):
            for _ in range(3):
                self.assert_http_status(
                    401,
                    lambda: main.auth_login(
                        main.LoginPayload(username="admin", password="wrong-password"),
                        self.request("POST", "/api/v1/auth/login"),
                    ),
                )
            self.assert_http_status(
                401,
                lambda: main.auth_login(
                    main.LoginPayload(username="admin", password="correct horse battery staple"),
                    self.request("POST", "/api/v1/auth/login"),
                ),
            )
        with main.sqlite_connection() as conn:
            row = main.fetch_user_by_username(conn, "admin")
            self.assertGreaterEqual(row["failed_login_attempts"], 3)
            self.assertTrue(row["locked_until"])

    def test_mandatory_and_regular_password_change_revoke_old_token(self):
        self.create_user(must_change=True)
        login = main.auth_login(
            main.LoginPayload(username="admin", password="correct horse battery staple"),
            self.request("POST", "/api/v1/auth/login"),
        )
        self.assertTrue(login["user"]["must_change_password"])
        request = self.request("POST", "/api/v1/auth/change-password", login["token"])
        request.state.user = login["user"]
        request.state.auth_session_id = main.jwt.decode(
            login["token"], main.AUTH_SECRET, algorithms=[main.AUTH_ALGORITHM]
        )["jti"]
        changed = main.auth_change_password(
            request,
            main.ChangePasswordPayload(
                current_password="correct horse battery staple",
                new_password="a new long passphrase for tests",
            ),
        )
        self.assertFalse(changed["user"]["must_change_password"])
        self.assertTrue(changed["token"])
        self.assertIsNone(main.token_user_from_request(self.request(token=login["token"])))
        self.assertIsNotNone(main.token_user_from_request(self.request(token=changed["token"])))

    def test_expired_token_and_user_disabled_after_issue_are_rejected(self):
        user = self.create_user()
        expired = main.jwt.encode(
            {
                "sub": str(user["id"]),
                "ver": 0,
                "exp": datetime.now(timezone.utc) - timedelta(seconds=1),
            },
            main.AUTH_SECRET,
            algorithm=main.AUTH_ALGORITHM,
        )
        self.assertIsNone(main.token_user_from_request(self.request(token=expired)))
        login = main.auth_login(
            main.LoginPayload(username="admin", password="correct horse battery staple"),
            self.request("POST", "/api/v1/auth/login"),
        )
        with main.sqlite_connection() as conn:
            conn.execute("UPDATE users SET active = 0 WHERE id = ?", (user["id"],))
            conn.commit()
        self.assertIsNone(main.token_user_from_request(self.request(token=login["token"])))

    def test_backend_permission_denial_returns_403(self):
        viewer = self.create_user("viewer", role="viewer")
        request = self.actor_request(viewer, "POST", "/api/v1/users")
        self.assert_http_status(403, lambda: main.require_permission(request, "users.create"))

    def test_user_crud_duplicate_reset_sessions_and_reactivation(self):
        actor = self.create_user()
        request = self.actor_request(actor)
        created = main.users_create(
            request,
            main.UserCreatePayload(
                username="operator.one",
                display_name="Operator One",
                role="operator",
                temporary_password="temporary passphrase 123",
            ),
        )["user"]
        self.assertTrue(created["must_change_password"])
        self.assert_http_status(
            409,
            lambda: main.users_create(
                request,
                main.UserCreatePayload(
                    username="operator.one",
                    display_name="Duplicate",
                    temporary_password="temporary passphrase 456",
                ),
            ),
        )
        updated = main.users_update(
            created["id"],
            self.actor_request(actor, "PATCH", f"/api/v1/users/{created['id']}"),
            main.UserUpdatePayload(display_name="Operator Updated"),
        )["user"]
        self.assertEqual("Operator Updated", updated["display_name"])
        main.users_disable(created["id"], self.actor_request(actor, path=f"/api/v1/users/{created['id']}/disable"))
        enabled = main.users_enable(created["id"], self.actor_request(actor, path=f"/api/v1/users/{created['id']}/enable"))["user"]
        self.assertTrue(enabled["active"])
        main.users_reset_password(
            created["id"],
            self.actor_request(actor, path=f"/api/v1/users/{created['id']}/reset-password"),
            main.UserResetPasswordPayload(temporary_password="another temporary passphrase"),
        )
        revoked = main.users_revoke_sessions(
            created["id"],
            self.actor_request(actor, path=f"/api/v1/users/{created['id']}/revoke-sessions"),
        )
        self.assertIn("revoked_sessions", revoked)

    def test_last_admin_cannot_demote_or_disable_self(self):
        actor = self.create_user()
        self.assert_http_status(
            409,
            lambda: main.users_update(
                actor["id"],
                self.actor_request(actor, "PATCH", f"/api/v1/users/{actor['id']}"),
                main.UserUpdatePayload(role="viewer"),
            ),
        )
        self.assert_http_status(
            409,
            lambda: main.users_disable(
                actor["id"],
                self.actor_request(actor, path=f"/api/v1/users/{actor['id']}/disable"),
            ),
        )
        with main.sqlite_connection() as conn:
            self.assertEqual("admin", main.fetch_user_by_id(conn, actor["id"])["role"])

    def test_audit_records_actor_correlation_and_never_password(self):
        actor = self.create_user()
        request = self.actor_request(actor)
        token = main.HTTP_REQUEST_ID.set("correlation-test")
        try:
            main.users_create(
                request,
                main.UserCreatePayload(
                    username="audit-user",
                    display_name="Audit User",
                    temporary_password="not stored in audit log",
                ),
            )
        finally:
            main.HTTP_REQUEST_ID.reset(token)
        with main.sqlite_connection() as conn:
            row = conn.execute("SELECT * FROM audit_log WHERE action = 'user.created'").fetchone()
            self.assertEqual(actor["id"], row["user_id"])
            self.assertEqual("correlation-test", row["correlation_id"])
            self.assertNotIn("not stored in audit log", row["metadata_json"])


if __name__ == "__main__":
    unittest.main()
