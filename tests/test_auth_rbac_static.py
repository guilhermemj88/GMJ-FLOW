import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKEND = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
FRONTEND = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")


class AuthRbacStaticTest(unittest.TestCase):
    def test_versioned_auth_and_admin_routes_exist(self):
        for route in (
            "/api/v1/auth/login", "/api/v1/auth/me", "/api/v1/auth/logout",
            "/api/v1/auth/change-password", "/api/v1/auth/revoke-sessions",
            "/api/v1/users", "/api/v1/roles", "/api/v1/permissions", "/api/v1/audit",
        ):
            self.assertIn(route, BACKEND)

    def test_backend_enforces_permissions_and_never_relies_on_frontend(self):
        self.assertIn("def require_permission(", BACKEND)
        self.assertIn("permission_for_protected_api_route(request)", BACKEND)
        self.assertIn("status_code=403", BACKEND)
        self.assertIn('require_permission(request, "users.manage_permissions")', BACKEND)
        self.assertIn('require_permission(request, "users.delete")', BACKEND)

    def test_security_event_investigation_uses_anomaly_permissions(self):
        self.assertIn('"/api/security/events"', BACKEND)
        self.assertIn('return "anomalies.view" if method == "GET" else "anomalies.manage"', BACKEND)

    def test_login_security_controls_are_present(self):
        self.assertIn("AUTH_DUMMY_PASSWORD_HASH", BACKEND)
        self.assertIn("failed_login_attempts", BACKEND)
        self.assertIn("locked_until", BACKEND)
        self.assertIn("login_rate_limited", BACKEND)
        self.assertIn("auth.login.denied", BACKEND)
        self.assertIn("last_login_at", BACKEND)
        self.assertIn("session_is_active", BACKEND)
        self.assertIn("auth_version", BACKEND)
        self.assertIn('os.getenv("GMJFLOW_INITIAL_ADMIN_PASSWORD", "")', BACKEND)
        self.assertNotIn('hash_password("admin")', BACKEND)

    def test_last_admin_and_soft_delete_protections_are_present(self):
        self.assertIn("require_active_admin_remaining(conn)", BACKEND)
        self.assertIn("Não é permitido desativar o próprio usuário", BACKEND)
        self.assertIn("deleted_at = ?", BACKEND)
        self.assertIn("Digite exatamente o username", BACKEND)

    def test_frontend_uses_permissions_and_handles_401_403(self):
        self.assertIn('id="usersNavButton"', FRONTEND)
        self.assertIn('data-required-permission="users.view"', FRONTEND)
        self.assertIn("function hasPermission(permissionKey)", FRONTEND)
        self.assertIn("if (response.status === 401)", FRONTEND)
        self.assertIn("if (response.status === 403)", FRONTEND)
        self.assertIn("showAccessDenied", FRONTEND)
        self.assertNotIn("currentAuthUser?.role === 'admin'", FRONTEND)
        self.assertNotIn("currentAuthUser?.role !== 'admin'", FRONTEND)

    def test_frontend_renders_inherited_direct_and_denied_states(self):
        self.assertIn("Herdada", FRONTEND)
        self.assertIn("Concedida diretamente", FRONTEND)
        self.assertIn("Negada diretamente", FRONTEND)
        self.assertIn("permission_overrides", FRONTEND)

    def test_passwords_tokens_and_hashes_are_not_rendered(self):
        table_markup = re.search(r'<tbody id="usersTable".*?</tbody>', FRONTEND, re.DOTALL)
        self.assertIsNotNone(table_markup)
        self.assertNotIn("password_hash", table_markup.group(0))
        self.assertNotIn("token_hash", FRONTEND)
        self.assertIn("password|passphrase|hash", FRONTEND)

    def test_must_change_password_still_blocks_application(self):
        self.assertIn("if (payload.user?.must_change_password)", FRONTEND)
        self.assertIn("showPasswordChange(payload.user)", FRONTEND)
        self.assertIn('"/api/v1/auth/change-password"', BACKEND)


if __name__ == "__main__":
    unittest.main()
